from __future__ import annotations

import base64
import http.client
import json
import os
import threading
import unittest
from http import HTTPStatus
from uuid import uuid4

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from presaga.crypto.key_custody import (
    OwnerRewrapApproval,
    OwnerRewrapRequest,
    UmbralOwnerKeyCustody,
)
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp
from presaga.provider.mongo_repository import MongoProviderRepository
from presaga.provider.repository import RepositoryConflict, RepositoryUnavailable
from presaga.provider.server import ProviderService, create_server
from presaga.storage.mongo_encrypted_store import MongoEncryptedStore


def _approval(request: OwnerRewrapRequest) -> OwnerRewrapApproval:
    return OwnerRewrapApproval(
        request_digest=request.request_digest,
        owner_aid=request.owner_aid,
        rotation_id=request.rotation_id,
        store_id=request.store_id,
        record_id=request.record_id,
        expected_object_revision=request.expected_object_revision,
        source_registration_id=request.source_registration_id,
        source_registration_version=request.source_registration_version,
        target_registration_id=request.target_registration_id,
        target_registration_version=request.target_registration_version,
        target_public_key_fingerprint=request.target_public_key_fingerprint,
        target_public_key=request.target_public_key,
    )


class MongoProviderServiceIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.uri = os.environ.get(
            "PRESAGA_MONGODB_URI",
            "mongodb://127.0.0.1:27017",
        )
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=1000)
            self.client.admin.command("ping")
        except PyMongoError as error:
            self.skipTest(f"MongoDB unavailable at {self.uri}: {error}")
        suffix = uuid4().hex
        self.restart_db = f"presaga_core005_restart_{suffix}"
        self.cas_db = f"presaga_core005_cas_{suffix}"
        self.backend = UmbralPREBackend()
        self.custody = UmbralOwnerKeyCustody(self.backend)
        self.management_token = "core005-management-token"
        self._servers: list[tuple[object, threading.Thread]] = []

    def tearDown(self) -> None:
        for server, thread in reversed(self._servers):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            mongo_client = getattr(server, "mongo_client", None)
            if mongo_client is not None:
                mongo_client.close()
        if hasattr(self, "client"):
            self.client.drop_database(self.restart_db)
            self.client.drop_database(self.cas_db)
            self.client.close()

    def _start_server(self, db_name: str):
        server = create_server(
            "127.0.0.1",
            0,
            backend=self.backend,
            management_token=self.management_token,
            mongo_uri=self.uri,
            mongo_db=db_name,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._servers.append((server, thread))
        return server

    def _stop_server(self, server) -> None:
        for index, (candidate, thread) in enumerate(self._servers):
            if candidate is server:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                server.mongo_client.close()
                self._servers.pop(index)
                return
        raise AssertionError("server was not tracked")

    def _request(
        self,
        server,
        path: str,
        payload: dict,
        *,
        management: bool = True,
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            server.server_address[1],
            timeout=5,
        )
        headers = {"Content-Type": "application/json"}
        if management:
            headers["Authorization"] = f"Bearer {self.management_token}"
        connection.request(
            "POST",
            path,
            body=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def test_http_rotation_recovers_from_mongo_and_finishes_after_restart(self) -> None:
        owner_aid = "alice@example.com:calendar"
        owner_v1 = self.backend.generate_keypair()
        owner_v2 = self.backend.generate_keypair()
        server = self._start_server(self.restart_db)

        status, _ = self._request(
            server,
            "/v1/management/agents",
            {"aid": owner_aid, "public_key_b64": _b64(owner_v1.public_key)},
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        service = server.provider_service
        stored = service.object_store.put(
            DataRecord(
                "core005-record",
                owner_aid,
                "calendar",
                "availability",
                1,
            ),
            b"available",
        )
        status, prepared_response = self._request(
            server,
            "/v1/management/agent-rotation-preparations",
            {
                "aid": owner_aid,
                "public_key_b64": _b64(owner_v2.public_key),
                "expected_version": 1,
            },
        )
        self.assertEqual(HTTPStatus.CREATED, status)
        rotation_id = prepared_response["agent"]["rotation_id"]
        stage_context = {
            "aid": owner_aid,
            "record_id": stored.record.record_id,
            "expected_version": 1,
            "rotation_id": rotation_id,
            "expected_object_revision": 1,
        }
        status, legacy_error = self._request(
            server,
            "/v1/management/agent-rotation-rewraps",
            {
                **stage_context,
                "source_private_key_b64": _b64(owner_v1.private_key),
            },
        )
        self.assertEqual(HTTPStatus.BAD_REQUEST, status)
        self.assertEqual("source_private_key_forbidden", legacy_error["error"])

        status, request_response = self._request(
            server,
            "/v1/management/agent-rotation-rewrap-requests",
            stage_context,
        )
        self.assertEqual(HTTPStatus.OK, status)
        request = OwnerRewrapRequest.from_payload(request_response["request"])
        artifact = self.custody.rewrap(
            request,
            owner_v1.private_key,
            _approval(request),
        )
        status, _ = self._request(
            server,
            "/v1/management/agent-rotation-rewraps",
            {**stage_context, "artifact": artifact.to_payload()},
        )
        self.assertEqual(HTTPStatus.OK, status)
        self._stop_server(server)

        restored = self._start_server(self.restart_db)
        restored_service = restored.provider_service
        pending = restored_service.app.registry.prepared_replacement(owner_aid)
        self.assertEqual(rotation_id, pending.rotation_id)
        self.assertEqual(
            2,
            restored_service.object_store.get(stored.record.record_id).object_revision,
        )

        status, _ = self._request(
            restored,
            "/v1/management/agent-rotation-commits",
            {
                "aid": owner_aid,
                "expected_version": 1,
                "rotation_id": rotation_id,
            },
        )
        self.assertEqual(HTTPStatus.OK, status)
        status, cleanup = self._request(
            restored,
            "/v1/management/agent-rotation-cleanups",
            {"aid": owner_aid, "rotation_id": rotation_id},
        )
        self.assertEqual(HTTPStatus.OK, status)
        self.assertTrue(cleanup["rotation"]["cleanup_completed"])
        cleaned = restored_service.object_store.get(stored.record.record_id)
        self.assertEqual(3, cleaned.object_revision)
        self.assertEqual(1, len(cleaned.owner_wraps))
        self.assertEqual(2, cleaned.owner_wraps[0].provenance.registration_version)
        state = MongoProviderRepository(
            self.client[self.restart_db]
        ).load()
        self.assertEqual(5, state["state_revision"])
        self.assertEqual("committed", state["rotation_journal"][0]["status"])
        self.assertTrue(state["rotation_journal"][0]["cleanup_completed"])

    def test_stale_provider_is_fenced_after_aggregate_revision_conflict(self) -> None:
        db = self.client[self.cas_db]
        first_app = PREProviderApp(self.backend)
        second_app = PREProviderApp(self.backend)
        first = ProviderService(
            first_app,
            MongoProviderRepository(db),
            object_store=MongoEncryptedStore(self.backend, db, first_app.registry),
        )
        second = ProviderService(
            second_app,
            MongoProviderRepository(db),
            object_store=MongoEncryptedStore(self.backend, db, second_app.registry),
        )
        first_key = self.backend.generate_keypair()
        second_key = self.backend.generate_keypair()
        first.register_agent(
            {
                "aid": "first@example.com:agent",
                "public_key_b64": _b64(first_key.public_key),
            }
        )
        with self.assertRaises(RepositoryConflict):
            second.register_agent(
                {
                    "aid": "second@example.com:agent",
                    "public_key_b64": _b64(second_key.public_key),
                }
            )
        self.assertTrue(second.persistence_fenced)
        with self.assertRaises(RepositoryUnavailable):
            second.audit_query({})
        persisted = MongoProviderRepository(db).load()
        self.assertEqual(
            ["first@example.com:agent"],
            [record["aid"] for record in persisted["agents"]],
        )

    def test_orphaned_mongo_objects_without_authoritative_state_fail_startup(self) -> None:
        db = self.client[self.cas_db]
        legacy_app = PREProviderApp(self.backend)
        owner = self.backend.generate_keypair()
        owner_aid = "orphan@example.com:agent"
        legacy_app.management.register_agent(owner_aid, owner.public_key)
        legacy_store = MongoEncryptedStore(self.backend, db, legacy_app.registry)
        legacy_store.put(
            DataRecord(
                "orphan-record",
                owner_aid,
                "calendar",
                "availability",
                1,
            ),
            b"orphaned",
        )

        restored_app = PREProviderApp(self.backend)
        with self.assertRaises(RepositoryUnavailable):
            ProviderService(
                restored_app,
                MongoProviderRepository(db),
                object_store=MongoEncryptedStore(
                    self.backend,
                    db,
                    restored_app.registry,
                ),
            )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()

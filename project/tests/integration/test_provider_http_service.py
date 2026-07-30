from __future__ import annotations

import base64
import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from presaga.crypto.hpke_kem_stub import HPKEKEMStub
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import JsonProviderRepository
from presaga.provider.server import ProviderService, make_handler
from presaga.storage.encrypted_store import EncryptedStore
from http.server import ThreadingHTTPServer


class ProviderHttpServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tempdir.name) / "provider-state.json"
        self.management_token = "test-management-token"
        self.backend = HPKEKEMStub()
        self.app = PREProviderApp(self.backend)
        self.store = EncryptedStore(self.backend, self.app.registry)
        self.service = ProviderService(
            self.app,
            JsonProviderRepository(self.state_file),
            object_store=self.store,
        )
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.service, self.management_token),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        management: bool = False,
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        if management:
            headers["Authorization"] = f"Bearer {self.management_token}"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def test_service_persists_issue_and_audits_a_data_token_flow(self):
        backend = self.backend
        owner = backend.generate_keypair()
        requester = backend.generate_keypair()
        owner_aid = "alice@example.com:calendar"
        requester_aid = "bob@example.com:scheduler"
        for aid, key in ((owner_aid, owner.public_key), (requester_aid, requester.public_key)):
            status, _ = self.request(
                "POST",
                "/v1/management/agents",
                {"aid": aid, "public_key_b64": _b64(key)},
                management=True,
            )
            self.assertEqual(201, status)
        status, _ = self.request("POST", "/v1/management/contact-rulebooks", {
            "owner_aid": owner_aid, "rulebook": [{"pattern": "bob@example.com:*", "budget": 1}],
        }, management=True)
        self.assertEqual(201, status)
        stored = self.store.put(
            DataRecord("cal-1", owner_aid, "calendar", "meeting", 1),
            b"calendar payload",
        )
        status, contact = self.request("POST", "/v1/contact-sessions", {
            "owner_aid": owner_aid, "requester_aid": requester_aid,
        })
        self.assertEqual(201, status)
        self.assertTrue(contact["contact_token"]["token_id"].startswith("ctok-"))

        now = datetime.now(timezone.utc)
        policy = {
            "policy_id": "calendar-meeting-read",
            "owner_aid": owner_aid,
            "requester_selector": {"type": "aid_exact", "value": requester_aid},
            "data_scope": {"data_classes": ["calendar"], "data_subclasses": ["meeting"], "record_ids": ["cal-1"]},
            "purposes": ["schedule_meeting"],
            "validity": {"not_before": (now - timedelta(minutes=1)).isoformat(), "not_after": (now + timedelta(minutes=5)).isoformat()},
            "limits": {"max_uses": 1},
            "version_constraints": {"min_version": 1, "max_version": 1},
        }
        status, _ = self.request("POST", "/v1/management/data-policies", policy, management=True)
        self.assertEqual(201, status)
        request = {
            "request_id": "req-1", "owner_aid": owner_aid, "requester_aid": requester_aid, "record_id": "cal-1",
            "data_class": "calendar", "data_subclass": "meeting", "purpose": "schedule_meeting", "version": 1,
            "requester_public_key_b64": _b64(requester.public_key), "timestamp": now.isoformat(),
        }
        status, denied = self.request("POST", "/v1/data-tokens", request)
        self.assertEqual(403, status)
        self.assertEqual("contact_session_required", denied["decision"]["reason"])
        request["contact_token_id"] = "ctok-unknown"
        status, denied = self.request("POST", "/v1/data-tokens", request)
        self.assertEqual(403, status)
        self.assertEqual("contact_session_not_found", denied["decision"]["reason"])
        request["contact_token_id"] = contact["contact_token"]["token_id"]
        denied_request = {
            **request,
            "request_id": "req-data-class-denied",
            "data_class": "mail",
            "data_subclass": "body",
        }
        status, denied = self.request(
            "POST",
            "/v1/data-tokens",
            denied_request,
        )
        self.assertEqual(403, status)
        self.assertEqual("data_class_denied", denied["decision"]["reason"])
        self.assertTrue(denied["audit_id"].startswith("audit-"))
        status, issued = self.request("POST", "/v1/data-tokens", request)
        self.assertEqual(201, status)
        self.assertTrue(issued["audit_id"].startswith("audit-"))
        self.assertEqual(contact["contact_token"]["token_id"], issued["data_token"]["contact_token_id"])
        self.assertEqual(contact["contact_token"]["contact_session_ref"], issued["data_token"]["contact_session_ref"])
        self.assertEqual(1, issued["data_token"]["owner_registration_version"])
        self.assertTrue(issued["data_token"]["owner_registration_id"].startswith("areg-"))
        self.assertEqual(
            "hpke-kem-stub",
            issued["data_token"]["owner_key_algorithm"],
        )
        self.assertEqual(64, len(issued["data_token"]["owner_public_key_fingerprint"]))
        token_id = issued["data_token"]["token_id"]
        context = self.store.context(stored.record)
        rekey = backend.generate_rekey(owner.private_key, requester.public_key, context)
        status, forbidden = self.request("POST", "/v1/re-encryptions", {
            "token_id": token_id, "request": request, "encrypted_dek_owner_b64": _b64(b"forged"), "rekey_b64": _b64(rekey),
        })
        self.assertEqual(403, status)
        self.assertEqual("raw_owner_wrap_forbidden", forbidden["error"])
        status, transformed = self.request("POST", "/v1/re-encryptions", {
            "token_id": token_id, "request": request, "rekey_b64": _b64(rekey),
        })
        self.assertEqual(200, status)
        self.assertEqual("allow", transformed["decision"])
        requester_dek = backend.unwrap_dek(
            base64.b64decode(transformed["transformed_encrypted_dek_b64"]),
            requester.private_key,
            context,
        )
        self.assertEqual(b"calendar payload", self.store.decrypt_with_dek(stored, requester_dek))
        status, audit = self.request("GET", "/v1/audit?decision=allow")
        self.assertEqual(200, status)
        self.assertEqual(2, audit["count"])
        self.assertTrue(self.state_file.exists())

        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.service, self.management_token),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        status, audit = self.request("GET", "/v1/audit")
        self.assertEqual(200, status)
        self.assertEqual(3, audit["count"])

    def test_management_routes_require_bearer_auth_and_legacy_route_is_absent(self):
        backend = HPKEKEMStub()
        key = backend.generate_keypair().public_key
        payload = {"aid": "alice@example.com:calendar", "public_key_b64": _b64(key)}

        status, response = self.request("POST", "/v1/management/agents", payload)
        self.assertEqual(401, status)
        self.assertEqual("management_authentication_required", response["error"])

        status, response = self.request("POST", "/v1/agents", payload, management=True)
        self.assertEqual(404, status)
        self.assertEqual("not_found", response["error"])

        status, response = self.request(
            "POST",
            "/v1/management/agents",
            payload,
            management=True,
        )
        self.assertEqual(201, status)
        self.assertEqual(1, response["agent"]["registration_version"])
        self.assertEqual("active", response["agent"]["status"])


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()

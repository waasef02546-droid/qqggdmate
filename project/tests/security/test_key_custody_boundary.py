from __future__ import annotations

import base64
import inspect
import json
import unittest

from presaga.crypto.key_custody import UmbralOwnerKeyCustody
from presaga.crypto.pre_interface import PREBackend
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp, TrustedManagementPlane
from presaga.provider.json_repository import to_jsonable
from presaga.provider.registry import AgentRegistry, RegistrationError
from presaga.provider.server import ProviderService
from presaga.storage.encrypted_store import EncryptedStore
from presaga.storage.mongo_encrypted_store import MongoEncryptedStore


class KeyCustodyBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = UmbralPREBackend()
        self.custody = UmbralOwnerKeyCustody(self.backend)
        self.app = PREProviderApp(self.backend)
        self.service = ProviderService(self.app)
        self.owner_v1 = self.backend.generate_keypair()
        self.owner_v2 = self.backend.generate_keypair()
        self.owner_aid = "alice@example.com:calendar"
        self.app.management.register_agent(self.owner_aid, self.owner_v1.public_key)
        self.store = EncryptedStore(self.backend, self.app.registry)
        self.service.object_store = self.store
        self.record = DataRecord(
            "custody-record-1",
            self.owner_aid,
            "calendar",
            "availability",
            1,
        )
        self.stored = self.store.put(self.record, b"available")
        self.prepared = self.app.management.prepare_agent_replacement(
            self.owner_aid,
            self.owner_v2.public_key,
            expected_version=1,
        )

    def _request(self, record_id: str | None = None, revision: int = 1):
        return self.app.management.build_agent_rewrap_request(
            self.owner_aid,
            expected_version=1,
            rotation_id=self.prepared.rotation_id,
            store=self.store,
            record_id=record_id or self.record.record_id,
            expected_object_revision=revision,
        )

    def _stage(self, artifact, record_id: str | None = None, revision: int = 1):
        return self.app.management.stage_agent_rewrap(
            self.owner_aid,
            expected_version=1,
            rotation_id=self.prepared.rotation_id,
            store=self.store,
            record_id=record_id or self.record.record_id,
            artifact=artifact,
            expected_object_revision=revision,
        )

    def test_provider_rotation_chain_has_no_private_key_parameter(self) -> None:
        callables = (
            TrustedManagementPlane.stage_agent_rewrap,
            AgentRegistry.stage_prepared_rewrap,
            EncryptedStore.stage_owner_rewrap,
            MongoEncryptedStore.stage_owner_rewrap,
        )
        for target in callables:
            with self.subTest(target=target.__qualname__):
                self.assertNotIn("source_private_key", inspect.signature(target).parameters)
        self.assertFalse(hasattr(PREBackend, "rewrap_dek"))
        with self.assertRaisesRegex(
            RegistrationError,
            "source_private_key_forbidden",
        ):
            self.service.stage_agent_rewrap(
                {
                    "aid": self.owner_aid,
                    "record_id": self.record.record_id,
                    "expected_version": 1,
                    "rotation_id": self.prepared.rotation_id,
                    "expected_object_revision": 1,
                    "source_private_key_b64": base64.b64encode(
                        self.owner_v1.private_key
                    ).decode("ascii"),
                }
            )

    def test_signed_artifact_stages_idempotently_and_conflicting_retry_fails(self) -> None:
        request = self._request()
        artifact = self.custody.rewrap(request, self.owner_v1.private_key)
        staged = self._stage(artifact)
        repeated = self._stage(artifact)
        self.assertEqual(2, staged.object_revision)
        self.assertEqual(staged, repeated)

        conflicting = self.custody.rewrap(request, self.owner_v1.private_key)
        self.assertNotEqual(
            artifact.target_encrypted_dek,
            conflicting.target_encrypted_dek,
        )
        with self.assertRaisesRegex(
            RegistrationError,
            "custody_artifact_conflict",
        ):
            self._stage(conflicting)

        self.app.management.commit_agent_replacement(
            self.owner_aid,
            expected_version=1,
            rotation_id=self.prepared.rotation_id,
        )
        active_wrap = self.store.resolve_active_owner_wrap(self.record.record_id)
        target_context = self.store.wrap_context(
            self.record,
            active_wrap.provenance,
        )
        dek = self.backend.unwrap_dek(
            active_wrap.encrypted_dek,
            self.owner_v2.private_key,
            target_context,
        )
        self.assertEqual(
            b"available",
            self.store.decrypt_with_dek(self.store.get(self.record.record_id), dek),
        )

    def test_cross_record_artifact_is_denied_without_mutation(self) -> None:
        second = self.store.put(
            DataRecord(
                "custody-record-2",
                self.owner_aid,
                "calendar",
                "availability",
                1,
            ),
            b"busy",
        )
        # Re-prepare so the immutable inventory includes both records.
        self.app.management.abort_agent_replacement(
            self.owner_aid,
            expected_version=1,
            rotation_id=self.prepared.rotation_id,
        )
        self.prepared = self.app.management.prepare_agent_replacement(
            self.owner_aid,
            self.owner_v2.public_key,
            expected_version=1,
        )
        first_request = self._request()
        first_artifact = self.custody.rewrap(
            first_request,
            self.owner_v1.private_key,
        )
        with self.assertRaisesRegex(
            RegistrationError,
            "custody_request_digest_mismatch",
        ):
            self._stage(first_artifact, second.record.record_id)
        self.assertEqual(1, self.store.get(second.record.record_id).object_revision)
        with self.assertRaisesRegex(RegistrationError, "owner_rewrap_incomplete"):
            self.app.management.commit_agent_replacement(
                self.owner_aid,
                expected_version=1,
                rotation_id=self.prepared.rotation_id,
            )

    def test_provider_visible_material_contains_no_source_key_or_dek(self) -> None:
        request = self._request()
        artifact = self.custody.rewrap(request, self.owner_v1.private_key)
        self._stage(artifact)
        source_wrap = self.stored.owner_wraps[0]
        source_context = self.store.wrap_context(
            self.record,
            source_wrap.provenance,
        )
        dek = self.backend.unwrap_dek(
            source_wrap.encrypted_dek,
            self.owner_v1.private_key,
            source_context,
        )
        provider_view = json.dumps(
            to_jsonable(
                {
                    "request": request.to_payload(),
                    "artifact": artifact.to_payload(),
                    "objects": self.store.snapshot(),
                    "journal": self.app.management.rotation_journal(),
                    "audit": self.app.audit_query(),
                }
            ),
            sort_keys=True,
        ).encode("utf-8")
        for secret in (self.owner_v1.private_key, dek):
            with self.subTest(secret_length=len(secret)):
                self.assertNotIn(secret, provider_view)
                self.assertNotIn(base64.b64encode(secret), provider_view)
                self.assertNotIn(secret.hex().encode("ascii"), provider_view)


if __name__ == "__main__":
    unittest.main()

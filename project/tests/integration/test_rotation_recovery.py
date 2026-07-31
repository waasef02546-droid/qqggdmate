from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from presaga.crypto.key_custody import OwnerRewrapRequest, UmbralOwnerKeyCustody
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import JsonProviderRepository
from presaga.provider.registry import RegistrationError
from presaga.provider.server import ProviderService
from presaga.storage.encrypted_store import EncryptedStore


class RotationRecoveryIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tempdir.name) / "provider-state.json"
        self.backend = UmbralPREBackend()
        self.custody = UmbralOwnerKeyCustody(self.backend)
        self.owner_v1 = self.backend.generate_keypair()
        self.owner_v2 = self.backend.generate_keypair()
        self.owner_aid = "alice@example.com:calendar"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _service(self) -> tuple[ProviderService, EncryptedStore]:
        app = PREProviderApp(self.backend)
        store = EncryptedStore(self.backend, app.registry)
        return (
            ProviderService(
                app,
                JsonProviderRepository(self.state_file),
                object_store=store,
            ),
            store,
        )

    def _prepare_and_stage(self) -> tuple[ProviderService, EncryptedStore, str]:
        service, store = self._service()
        service.register_agent(
            {
                "aid": self.owner_aid,
                "public_key_b64": _b64(self.owner_v1.public_key),
            }
        )
        stored = store.put(
            DataRecord(
                "cal-recovery-1",
                self.owner_aid,
                "calendar",
                "availability",
                1,
            ),
            b"available",
        )
        prepared = service.prepare_agent_replacement(
            {
                "aid": self.owner_aid,
                "public_key_b64": _b64(self.owner_v2.public_key),
                "expected_version": 1,
            }
        )
        rotation_id = prepared["rotation_id"]
        stage_context = {
            "aid": self.owner_aid,
            "record_id": stored.record.record_id,
            "expected_version": 1,
            "rotation_id": rotation_id,
            "expected_object_revision": 1,
        }
        request = OwnerRewrapRequest.from_payload(
            service.export_agent_rewrap_request(stage_context)
        )
        artifact = self.custody.rewrap(request, self.owner_v1.private_key)
        service.stage_agent_rewrap(
            {**stage_context, "artifact": artifact.to_payload()}
        )
        return service, store, rotation_id

    def test_restart_restores_pending_rotation_then_commit_and_cleanup_are_durable(self) -> None:
        _, _, rotation_id = self._prepare_and_stage()

        restored, restored_store = self._service()
        pending = restored.app.registry.prepared_replacement(self.owner_aid)
        self.assertEqual(rotation_id, pending.rotation_id)
        self.assertEqual(2, restored_store.get("cal-recovery-1").object_revision)

        restored.commit_agent_replacement(
            {
                "aid": self.owner_aid,
                "expected_version": 1,
                "rotation_id": rotation_id,
            }
        )
        cleaned = restored.cleanup_agent_rotation(
            {"aid": self.owner_aid, "rotation_id": rotation_id}
        )
        self.assertTrue(cleaned["cleanup_completed"])
        stored = restored_store.get("cal-recovery-1")
        self.assertEqual(3, stored.object_revision)
        self.assertEqual(1, len(stored.owner_wraps))
        self.assertEqual(2, stored.owner_wraps[0].provenance.registration_version)

        repeated = restored.cleanup_agent_rotation(
            {"aid": self.owner_aid, "rotation_id": rotation_id}
        )
        self.assertTrue(repeated["cleanup_completed"])
        self.assertEqual(3, restored_store.get("cal-recovery-1").object_revision)

        final, final_store = self._service()
        journal = final.app.management.rotation_journal()
        self.assertEqual(1, len(journal))
        self.assertEqual("committed", journal[0].status)
        self.assertTrue(journal[0].cleanup_completed)
        self.assertEqual(3, final_store.get("cal-recovery-1").object_revision)

    def test_abort_cleanup_removes_only_this_rotation_target(self) -> None:
        service, store, rotation_id = self._prepare_and_stage()
        service.abort_agent_replacement(
            {
                "aid": self.owner_aid,
                "expected_version": 1,
                "rotation_id": rotation_id,
            }
        )
        service.cleanup_agent_rotation(
            {"aid": self.owner_aid, "rotation_id": rotation_id}
        )
        cleaned = store.get("cal-recovery-1")
        self.assertEqual(3, cleaned.object_revision)
        self.assertEqual(1, len(cleaned.owner_wraps))
        self.assertEqual(1, cleaned.owner_wraps[0].provenance.registration_version)
        self.assertIsNone(cleaned.owner_wraps[0].rotation_id)

    def test_restore_rejects_journal_inconsistent_with_registry(self) -> None:
        self._prepare_and_stage()
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        state["rotation_journal"][0]["current_version"] = 99
        self.state_file.write_text(json.dumps(state), encoding="utf-8")

        with self.assertRaisesRegex(RegistrationError, "rotation_version_invalid"):
            self._service()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()

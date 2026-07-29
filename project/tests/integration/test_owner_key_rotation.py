from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import (
    DataAccessRequest,
    DataRecord,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.provider.app import PREProviderApp
from presaga.provider.registry import RegistrationError
from presaga.storage.encrypted_store import EncryptedStore


class OwnerKeyRotationIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = ToyPRE()
        self.app = PREProviderApp(self.backend)
        self.owner_v1 = self.backend.generate_keypair()
        self.owner_v2 = self.backend.generate_keypair()
        self.owner_v3 = self.backend.generate_keypair()
        self.requester = self.backend.generate_keypair()
        self.owner_aid = "alice@example.com:calendar"
        self.requester_aid = "bob@example.com:scheduler"
        self.owner_registration = self.app.management.register_agent(
            self.owner_aid, self.owner_v1.public_key
        )
        self.app.management.register_agent(self.requester_aid, self.requester.public_key)
        self.store = EncryptedStore(self.backend, self.app.registry)
        self.record = DataRecord(
            "cal-rotation-1", self.owner_aid, "calendar", "availability", 1
        )
        self.stored = self.store.put(self.record, b"available")

    def _prepare(self, public_key: bytes):
        return self.app.management.prepare_agent_replacement(
            self.owner_aid,
            public_key,
            expected_version=self.app.registry.resolve_active(
                self.owner_aid
            ).registration_version,
        )

    def _stage(self, prepared, record_id: str, private_key: bytes, revision: int):
        return self.app.management.stage_agent_rewrap(
            self.owner_aid,
            expected_version=prepared.current_version,
            rotation_id=prepared.rotation_id,
            store=self.store,
            record_id=record_id,
            source_private_key=private_key,
            expected_object_revision=revision,
        )

    def test_prepare_stage_commit_retains_source_and_selects_target(self) -> None:
        prepared = self._prepare(self.owner_v2.public_key)
        staged = self._stage(
            prepared,
            self.record.record_id,
            self.owner_v1.private_key,
            self.stored.object_revision,
        )
        self.assertEqual(2, len(staged.owner_wraps))
        self.assertEqual(1, self.app.registry.resolve_active(self.owner_aid).registration_version)

        activated = self.app.management.commit_agent_replacement(
            self.owner_aid,
            expected_version=prepared.current_version,
            rotation_id=prepared.rotation_id,
        )
        self.assertEqual(2, activated.registration_version)
        active_wrap = self.store.resolve_active_owner_wrap(self.record.record_id)
        self.assertEqual(activated.registration_version, active_wrap.provenance.registration_version)
        dek = self.backend.unwrap_dek(
            active_wrap.encrypted_dek,
            self.owner_v2.private_key,
            self.store.context(self.record),
        )
        self.assertEqual(b"available", self.store.decrypt_with_dek(staged, dek))

    def test_partial_failure_blocks_commit_and_abort_leaves_source_active(self) -> None:
        second = self.store.put(
            DataRecord("cal-rotation-2", self.owner_aid, "calendar", "availability", 1),
            b"busy",
        )
        prepared = self._prepare(self.owner_v2.public_key)
        self._stage(
            prepared,
            self.record.record_id,
            self.owner_v1.private_key,
            self.stored.object_revision,
        )
        with self.assertRaisesRegex(RegistrationError, "owner_rewrap_incomplete"):
            self.app.management.commit_agent_replacement(
                self.owner_aid,
                expected_version=1,
                rotation_id=prepared.rotation_id,
            )
        self.app.management.abort_agent_replacement(
            self.owner_aid,
            expected_version=1,
            rotation_id=prepared.rotation_id,
        )
        self.assertEqual(1, self.app.registry.resolve_active(self.owner_aid).registration_version)
        self.assertEqual(1, self.store.resolve_active_owner_wrap(second).provenance.registration_version)

    def test_owner_rotation_denies_stale_token_before_use(self) -> None:
        now = datetime.now(timezone.utc)
        self.app.management.set_contact_rulebook(
            self.owner_aid, [{"pattern": self.requester_aid, "budget": 2}]
        )
        self.app.management.add_data_policy(
            DataSharingPolicy(
                "rotation-policy",
                self.owner_aid,
                RequesterSelector("aid_exact", self.requester_aid),
                DataScope(["calendar"], ["availability"], [self.record.record_id]),
                ["schedule"],
                Validity(now - timedelta(minutes=1), now + timedelta(minutes=5)),
                Limits(1),
                VersionConstraints(1, 1),
            )
        )
        contact = self.app.issue_contact_session(self.owner_aid, self.requester_aid)
        request = DataAccessRequest(
            "rotation-request",
            self.owner_aid,
            self.requester_aid,
            self.record.record_id,
            "calendar",
            "availability",
            "schedule",
            1,
            self.requester.public_key,
            now,
        )
        issuance = self.app.request_data_token(contact_token=contact, request=request, now=now)
        self.assertIsNotNone(issuance.token)
        prepared = self._prepare(self.owner_v2.public_key)
        self._stage(
            prepared,
            self.record.record_id,
            self.owner_v1.private_key,
            self.stored.object_revision,
        )
        self.app.management.commit_agent_replacement(
            self.owner_aid,
            expected_version=1,
            rotation_id=prepared.rotation_id,
        )
        result = self.app.request_re_encryption(
            contact_token=contact,
            token=issuance.token,
            request=request,
            stored=self.store.get(self.record.record_id),
            rekey=b"x" * 32,
            now=now,
        )
        self.assertEqual("deny", result.decision)
        self.assertEqual("owner_registration_stale", result.reason)
        self.assertEqual(1, issuance.token.remaining_uses)


if __name__ == "__main__":
    unittest.main()

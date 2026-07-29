from __future__ import annotations

import unittest
import tempfile
from dataclasses import replace
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
from presaga.provider.json_repository import JsonProviderRepository
from presaga.provider.registry import RegistrationError
from presaga.provider.server import ProviderService
from presaga.storage.encrypted_store import EncryptedStore


class ManagementDataPlaneIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.backend = ToyPRE()
        self.app = PREProviderApp(self.backend)
        self.owner = self.backend.generate_keypair()
        self.requester = self.backend.generate_keypair()
        self.attacker = self.backend.generate_keypair()
        self.owner_aid = "alice@example.com:calendar"
        self.requester_aid = "bob@example.com:scheduler"
        self.owner_registration = self.app.management.register_agent(self.owner_aid, self.owner.public_key)
        self.requester_registration = self.app.management.register_agent(
            self.requester_aid,
            self.requester.public_key,
        )
        self.store = EncryptedStore(self.backend, self.app.registry)
        self.record = DataRecord(
            "cal-1", self.owner_aid, "calendar", "availability", 1
        )
        self.stored = self.store.put(self.record, b"available")
        self.app.management.set_contact_rulebook(
            self.owner_aid,
            [{"pattern": self.requester_aid, "budget": 10}],
        )
        self.app.management.add_data_policy(
            DataSharingPolicy(
                policy_id="registered-key-policy",
                owner_aid=self.owner_aid,
                requester_selector=RequesterSelector(type="aid_exact", value=self.requester_aid),
                data_scope=DataScope(
                    data_classes=["calendar"],
                    data_subclasses=["availability"],
                    record_ids=["cal-1"],
                ),
                purposes=["schedule"],
                validity=Validity(self.now - timedelta(minutes=1), self.now + timedelta(minutes=5)),
                limits=Limits(max_uses=1),
                version_constraints=VersionConstraints(1, 1),
            )
        )
        self.contact = self.app.issue_contact_session(self.owner_aid, self.requester_aid)
        self.assertIsNotNone(self.contact)
        self.request = DataAccessRequest(
            request_id="req-registered-key",
            owner_aid=self.owner_aid,
            requester_aid=self.requester_aid,
            record_id="cal-1",
            data_class="calendar",
            data_subclass="availability",
            purpose="schedule",
            version=1,
            requester_public_key=self.requester.public_key,
            timestamp=self.now,
        )

    def test_data_plane_has_no_registration_mutation_methods(self) -> None:
        self.assertFalse(hasattr(self.app, "register_agent"))
        self.assertFalse(hasattr(self.app, "replace_agent"))
        self.assertFalse(hasattr(self.app, "revoke_agent"))
        self.assertFalse(hasattr(self.app, "add_data_policy"))
        self.assertFalse(hasattr(self.app, "set_contact_rulebook"))

    def test_issuance_derives_binding_from_authoritative_registration(self) -> None:
        without_assertion = replace(self.request, requester_public_key=None)
        result = self.app.request_data_token(
            contact_token=self.contact,
            request=without_assertion,
            now=max(self.now, self.contact.not_before),
        )

        self.assertIsNotNone(result.token)
        self.assertEqual(
            self.requester_registration.public_key_fingerprint,
            result.token.requester_public_key_hash,
        )
        self.assertEqual(
            self.requester_registration.registration_version,
            result.token.requester_registration_version,
        )
        self.assertEqual(
            self.owner_registration.public_key_fingerprint,
            result.token.owner_public_key_fingerprint,
        )
        self.assertEqual(
            self.owner_registration.registration_version,
            result.token.owner_registration_version,
        )
        self.assertEqual(
            self.owner_registration.registration_id,
            result.token.owner_registration_id,
        )
        self.assertEqual(
            self.owner_registration.key_algorithm,
            result.token.owner_key_algorithm,
        )

    def test_caller_selected_key_is_rejected_before_issuance(self) -> None:
        forged = replace(self.request, requester_public_key=self.attacker.public_key)

        result = self.app.request_data_token(
            contact_token=self.contact,
            request=forged,
            now=self.now,
        )

        self.assertIsNone(result.token)
        self.assertEqual("requester_key_mismatch", result.decision.reason)

    def test_rotation_between_issuance_and_consumption_invalidates_token(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=max(self.now, self.contact.not_before),
        )
        self.assertIsNotNone(issued.token, issued.decision.reason)
        self.app.management.replace_agent(
            self.requester_aid,
            self.attacker.public_key,
            expected_version=self.requester_registration.registration_version,
        )

        result = self.app.request_re_encryption(
            contact_token=self.contact,
            token=issued.token,
            request=replace(self.request, requester_public_key=None),
            stored=self.stored,
            rekey=b"rekey",
            now=max(self.now, self.contact.not_before),
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("requester_registration_stale", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)

    def test_revocation_between_issuance_and_consumption_invalidates_token(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)
        self.app.management.revoke_agent(
            self.requester_aid,
            expected_version=self.requester_registration.registration_version,
        )

        result = self.app.request_re_encryption(
            contact_token=self.contact,
            token=issued.token,
            request=self.request,
            stored=self.stored,
            rekey=b"rekey",
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("registration_not_active", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)

    def test_json_restart_preserves_versioned_registration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonProviderRepository(f"{directory}/provider-state.json")
            app = PREProviderApp(self.backend)
            service = ProviderService(app, repository)
            service.register_agent(
                {"aid": self.requester_aid, "public_key_b64": _b64(self.requester.public_key)}
            )
            replacement = service.replace_agent(
                {
                    "aid": self.requester_aid,
                    "public_key_b64": _b64(self.attacker.public_key),
                    "expected_version": 1,
                }
            )

            restored = ProviderService(PREProviderApp(self.backend), repository)
            record = restored.app.registry.resolve_active(self.requester_aid)

        self.assertEqual(2, replacement["registration_version"])
        self.assertEqual(2, record.registration_version)
        self.assertEqual(self.attacker.public_key, record.public_key)
        self.assertEqual(replacement["public_key_fingerprint"], record.public_key_fingerprint)

    def test_legacy_json_registration_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonProviderRepository(f"{directory}/provider-state.json")
            state = repository.empty_state()
            state["schema_version"] = 1
            state["agents"] = [
                {
                    "aid": self.requester_aid,
                    "public_key_b64": _b64(self.requester.public_key),
                }
            ]
            repository.save(state)

            restored = ProviderService(PREProviderApp(self.backend), repository)
            record = restored.app.registry.get(self.requester_aid)

        self.assertEqual("legacy_unverified", record.status)
        with self.assertRaisesRegex(RegistrationError, "registration_not_active"):
            restored.app.registry.resolve_active(self.requester_aid)


def _b64(value: bytes) -> str:
    import base64

    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()

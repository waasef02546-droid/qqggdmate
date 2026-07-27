from __future__ import annotations

import base64
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
from presaga.provider.json_repository import JsonProviderRepository, to_jsonable
from presaga.provider.server import ProviderService
from presaga.storage.encrypted_store import EncryptedStore


class ContactDataBindingIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.backend = ToyPRE()
        self.app = PREProviderApp(self.backend)
        self.owner = self.backend.generate_keypair()
        self.requester = self.backend.generate_keypair()
        self.owner_aid = "alice@mail.com:calendar_agent"
        self.requester_aid = "bob@mail.com:scheduler_agent"
        self.app.set_contact_rulebook(
            self.owner_aid,
            [{"pattern": "bob@mail.com:*", "budget": 4}],
        )
        self.contact = self.app.saga_adapter.issue_contact_token(
            owner_aid=self.owner_aid,
            requester_aid=self.requester_aid,
            now=self.now,
        )
        self.assertIsNotNone(self.contact)
        self.record = DataRecord(
            record_id="cal-binding-001",
            owner_aid=self.owner_aid,
            data_class="calendar",
            data_subclass="availability",
            version=1,
        )
        self.store = EncryptedStore(self.backend)
        self.stored = self.store.put(self.record, b"Alice is free at 10:00.", self.owner.public_key)
        self.app.add_data_policy(
            DataSharingPolicy(
                policy_id="binding-policy",
                owner_aid=self.owner_aid,
                requester_selector=RequesterSelector(type="aid_exact", value=self.requester_aid),
                data_scope=DataScope(
                    data_classes=["calendar"],
                    data_subclasses=["availability"],
                    record_ids=[self.record.record_id],
                ),
                purposes=["schedule_meeting"],
                validity=Validity(self.now - timedelta(minutes=1), self.now + timedelta(minutes=10)),
                limits=Limits(max_uses=1),
                version_constraints=VersionConstraints(1, 1),
            )
        )
        self.request = DataAccessRequest(
            request_id="binding-request",
            owner_aid=self.owner_aid,
            requester_aid=self.requester_aid,
            record_id=self.record.record_id,
            data_class=self.record.data_class,
            data_subclass=self.record.data_subclass,
            purpose="schedule_meeting",
            version=self.record.version,
            requester_public_key=self.requester.public_key,
            timestamp=self.now,
        )
        self.rekey = self.backend.generate_rekey(
            self.owner.private_key,
            self.requester.public_key,
            self.store.context(self.record),
        )

    def test_issuance_requires_contact_and_signs_exact_session_binding(self) -> None:
        missing = self.app.request_data_token(
            contact_token=None,
            request=self.request,
            now=self.now,
        )
        self.assertIsNone(missing.token)
        self.assertEqual("contact_session_required", missing.decision.reason)

        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )

        self.assertIsNotNone(issued.token)
        self.assertEqual(self.contact.token_id, issued.token.contact_token_id)
        self.assertEqual(self.contact.contact_session_ref, issued.token.contact_session_ref)
        self.assertEqual(self.contact.expires_at, issued.token.expires_at)

    def test_re_encryption_rejects_a_different_valid_contact_session(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        other_contact = self.app.saga_adapter.issue_contact_token(
            owner_aid=self.owner_aid,
            requester_aid=self.requester_aid,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)
        self.assertIsNotNone(other_contact)

        result = self.app.request_re_encryption(
            contact_token=other_contact,
            token=issued.token,
            request=self.request,
            encrypted_dek_owner=self.stored.encrypted_dek_owner,
            rekey=self.rekey,
            now=self.now,
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("contact_session_mismatch", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)

    def test_re_encryption_revalidates_contact_expiry(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)

        result = self.app.request_re_encryption(
            contact_token=self.contact,
            token=issued.token,
            request=self.request,
            encrypted_dek_owner=self.stored.encrypted_dek_owner,
            rekey=self.rekey,
            now=self.contact.expires_at + timedelta(microseconds=1),
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("contact_token_expired", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)

    def test_re_encryption_rejects_missing_bound_contact_state(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)

        result = self.app.request_re_encryption(
            contact_token=None,
            token=issued.token,
            request=self.request,
            encrypted_dek_owner=self.stored.encrypted_dek_owner,
            rekey=self.rekey,
            now=self.now,
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("contact_session_not_found", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)

    def test_legacy_unbound_data_token_fails_closed(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)
        legacy_token = to_jsonable(issued.token)
        legacy_token.pop("contact_token_id")
        legacy_token.pop("contact_session_ref")
        with tempfile.TemporaryDirectory() as directory:
            repository = JsonProviderRepository(Path(directory) / "provider-state.json")
            state = repository.empty_state()
            state["contact_tokens"] = [to_jsonable(self.contact)]
            state["data_tokens"] = [legacy_token]
            repository.save(state)
            restored = ProviderService(PREProviderApp(self.backend), repository)
            restored_token = restored.data_tokens[issued.token.token_id]
            self.assertEqual("", restored_token.contact_token_id)
            self.assertEqual("", restored_token.contact_session_ref)

            status, response = restored.request_re_encryption(
                {
                    "token_id": restored_token.token_id,
                    "request": {
                        "request_id": self.request.request_id,
                        "owner_aid": self.request.owner_aid,
                        "requester_aid": self.request.requester_aid,
                        "record_id": self.request.record_id,
                        "data_class": self.request.data_class,
                        "data_subclass": self.request.data_subclass,
                        "purpose": self.request.purpose,
                        "version": self.request.version,
                        "requester_public_key_b64": _b64(self.request.requester_public_key),
                        "timestamp": self.request.timestamp.isoformat(),
                    },
                    "encrypted_dek_owner_b64": _b64(self.stored.encrypted_dek_owner),
                    "rekey_b64": _b64(self.rekey),
                }
            )

        self.assertEqual(403, status)
        self.assertEqual("contact_session_not_found", response["reason"])

    def test_re_encryption_rejects_a_forged_bound_contact_token(self) -> None:
        issued = self.app.request_data_token(
            contact_token=self.contact,
            request=self.request,
            now=self.now,
        )
        self.assertIsNotNone(issued.token)
        forged_contact = replace(self.contact, issuer_signature="forged")

        result = self.app.request_re_encryption(
            contact_token=forged_contact,
            token=issued.token,
            request=self.request,
            encrypted_dek_owner=self.stored.encrypted_dek_owner,
            rekey=self.rekey,
            now=self.now,
        )

        self.assertEqual("deny", result.decision)
        self.assertEqual("contact_token_signature_invalid", result.reason)
        self.assertEqual(1, issued.token.remaining_uses)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()

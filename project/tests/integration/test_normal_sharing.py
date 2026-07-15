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
from presaga.provider.audit import AuditLogger
from presaga.provider.data_policy import DataPolicyEvaluator
from presaga.provider.pre_proxy import PREProxy
from presaga.provider.token_service import TokenService
from presaga.storage.encrypted_store import EncryptedStore


class NormalSharingIntegrationTest(unittest.TestCase):
    def test_policy_token_pre_store_full_flow(self):
        backend = ToyPRE()
        owner = backend.generate_keypair()
        requester = backend.generate_keypair()
        store = EncryptedStore(backend)

        record = DataRecord(
            record_id="cal-001",
            owner_aid="alice@mail.com:calendar_agent",
            data_class="calendar",
            data_subclass="availability",
            version=1,
        )
        plaintext = b"Alice is free from 10:00 to 11:00."
        stored = store.put(record, plaintext, owner.public_key)

        now = datetime.now(timezone.utc)
        policy = DataSharingPolicy(
            policy_id="policy-calendar-v1",
            owner_aid=record.owner_aid,
            requester_selector=RequesterSelector(type="aid_exact", value="bob@mail.com:scheduler_agent"),
            data_scope=DataScope(data_classes=["calendar"], data_subclasses=["availability"], record_ids=["cal-001"]),
            purposes=["schedule_meeting"],
            validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
            limits=Limits(max_uses=1, max_records=1),
            version_constraints=VersionConstraints(min_version=1, max_version=1),
        )
        request = DataAccessRequest(
            request_id="req-1",
            owner_aid=record.owner_aid,
            requester_aid="bob@mail.com:scheduler_agent",
            record_id=record.record_id,
            data_class=record.data_class,
            data_subclass=record.data_subclass,
            purpose="schedule_meeting",
            version=record.version,
            requester_public_key=requester.public_key,
        )

        decision = DataPolicyEvaluator([policy]).evaluate(request)
        self.assertEqual(decision.effect, "allow")

        token_service = TokenService(b"issuer-secret")
        token = token_service.issue_data_token(decision, request)
        audit = AuditLogger()
        proxy = PREProxy(backend, token_service, audit)
        rekey = backend.generate_rekey(owner.private_key, requester.public_key, store.context(record))

        result = proxy.transform(
            token=token,
            request=request,
            encrypted_dek_owner=stored.encrypted_dek_owner,
            rekey=rekey,
        )

        self.assertEqual(result.decision, "allow")
        self.assertIsNotNone(result.transformed_encrypted_dek)
        requester_dek = backend.unwrap_dek(result.transformed_encrypted_dek, requester.private_key, store.context(record))
        recovered = store.decrypt_with_dek(stored, requester_dek)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(token.remaining_uses, 0)
        self.assertFalse(audit.events[-1].provider_saw_plaintext_dek)
        self.assertFalse(audit.events[-1].provider_saw_plaintext_data)

        denied = proxy.transform(
            token=token,
            request=request,
            encrypted_dek_owner=stored.encrypted_dek_owner,
            rekey=rekey,
        )
        self.assertEqual(denied.decision, "deny")
        self.assertEqual(denied.reason, "token_exhausted")


if __name__ == "__main__":
    unittest.main()

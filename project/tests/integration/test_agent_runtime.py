from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from presaga.agent import AgentMaterial, PREAgent
from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import (
    DataRecord,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.provider.app import PREProviderApp
from presaga.storage.encrypted_store import EncryptedStore


class PREAgentRuntimeIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = ToyPRE()
        self.provider = PREProviderApp(self.backend)
        self.alice = self._agent("alice@mail.com:calendar_agent")
        self.bob = self._agent("bob@mail.com:scheduler_agent")
        self.mallory = self._agent("mallory@mail.com:assistant_agent")
        for agent in (self.alice, self.bob, self.mallory):
            agent.register_with_provider()
        self.store = EncryptedStore(self.backend, self.provider.registry)
        self.alice.attach_store("calendar", self.store)
        self.record = DataRecord(
            record_id="cal-runtime-001",
            owner_aid=self.alice.aid,
            data_class="calendar",
            data_subclass="availability",
            version=1,
        )
        self.stored = self.store.put(self.record, b"Alice is free at 10:00.")
        now = datetime.now(timezone.utc)
        self.provider.management.add_data_policy(
            DataSharingPolicy(
                policy_id="runtime-calendar-policy",
                owner_aid=self.alice.aid,
                requester_selector=RequesterSelector(type="aid_exact", value=self.bob.aid),
                data_scope=DataScope(data_classes=["calendar"], data_subclasses=["availability"], record_ids=[self.record.record_id]),
                purposes=["schedule_meeting"],
                validity=Validity(now - timedelta(minutes=1), now + timedelta(minutes=5)),
                limits=Limits(max_uses=1),
                version_constraints=VersionConstraints(1, 1),
            )
        )
        self.alice.set_contact_policy([
            {"pattern": self.bob.aid, "budget": 5},
            {"pattern": self.mallory.aid, "budget": 5},
        ])

    def _agent(self, aid: str) -> PREAgent:
        pair = self.backend.generate_keypair()
        return PREAgent(
            AgentMaterial(aid=aid, public_key=pair.public_key, private_key=pair.private_key),
            self.provider,
            self.provider.management,
        )

    def test_alice_bob_normal_data_sharing_lifecycle(self) -> None:
        self.assertIsNotNone(self.bob.open_contact_session(self.alice.aid))
        token = self.bob.request_data_token(self.record, "schedule_meeting")
        self.assertIsNotNone(token)
        transformed = self.bob.request_re_encryption(token_id=token.token_id, owner=self.alice, store=self.store, record_id=self.record.record_id)
        self.assertEqual(b"Alice is free at 10:00.", self.bob.decrypt_stored_object(store=self.store, record_id=self.record.record_id, transformed_encrypted_dek=transformed))
        self.assertEqual(["registered", "contact_session", "data_token", "re_encryption", "decrypt", "audit"], [event.phase for event in self.bob.lifecycle])

    def test_mallory_contact_allowed_but_data_denied(self) -> None:
        self.assertIsNotNone(self.mallory.open_contact_session(self.alice.aid))
        self.assertIsNone(self.mallory.request_data_token(self.record, "schedule_meeting"))
        self.assertEqual("contact_session", self.mallory.lifecycle[-2].phase)
        self.assertEqual("deny", self.mallory.lifecycle[-1].decision)
        self.assertEqual("requester_mismatch", self.mallory.lifecycle[-1].reason)

    def test_consumed_token_cannot_be_reused(self) -> None:
        self.bob.open_contact_session(self.alice.aid)
        token = self.bob.request_data_token(self.record, "schedule_meeting")
        self.assertIsNotNone(token)
        self.assertIsNotNone(self.bob.request_re_encryption(token_id=token.token_id, owner=self.alice, store=self.store, record_id=self.record.record_id))
        self.assertIsNone(self.bob.request_re_encryption(token_id=token.token_id, owner=self.alice, store=self.store, record_id=self.record.record_id))
        self.assertEqual("token_exhausted", self.bob.lifecycle[-1].reason)


if __name__ == "__main__":
    unittest.main()

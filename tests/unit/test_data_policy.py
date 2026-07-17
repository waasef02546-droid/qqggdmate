from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import (
    DataAccessRequest,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.provider.data_policy import DataPolicyEvaluator


class DataPolicyEvaluatorTest(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.backend = ToyPRE()
        self.requester = self.backend.generate_keypair()
        self.policy = DataSharingPolicy(
            policy_id="policy-calendar-v1",
            owner_aid="alice@mail.com:calendar_agent",
            requester_selector=RequesterSelector(type="aid_exact", value="bob@mail.com:scheduler_agent"),
            data_scope=DataScope(
                data_classes=["calendar"],
                data_subclasses=["availability"],
                record_prefixes=["cal-"],
            ),
            purposes=["schedule_meeting"],
            validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
            limits=Limits(max_uses=2, max_records=10),
            version_constraints=VersionConstraints(min_version=1, max_version=3),
        )
        self.evaluator = DataPolicyEvaluator([self.policy])

    def request(self, **overrides):
        data = {
            "request_id": "req-1",
            "owner_aid": "alice@mail.com:calendar_agent",
            "requester_aid": "bob@mail.com:scheduler_agent",
            "record_id": "cal-001",
            "data_class": "calendar",
            "data_subclass": "availability",
            "purpose": "schedule_meeting",
            "version": 2,
            "requester_public_key": self.requester.public_key,
        }
        data.update(overrides)
        return DataAccessRequest(**data)

    def test_allows_matching_request(self):
        decision = self.evaluator.evaluate(self.request())
        self.assertEqual(decision.effect, "allow")
        self.assertEqual(decision.reason, "policy_match")
        self.assertEqual(decision.max_uses, 2)

    def test_denies_wrong_requester(self):
        decision = self.evaluator.evaluate(self.request(requester_aid="mallory@mail.com:agent"))
        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "requester_mismatch")

    def test_denies_wrong_data_class(self):
        decision = self.evaluator.evaluate(self.request(data_class="mail", data_subclass="body"))
        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "data_class_denied")

    def test_denies_purpose_mismatch(self):
        decision = self.evaluator.evaluate(self.request(purpose="expense_report"))
        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "purpose_mismatch")

    def test_denies_version_out_of_bounds(self):
        decision = self.evaluator.evaluate(self.request(version=4))
        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "version_out_of_bounds")


if __name__ == "__main__":
    unittest.main()

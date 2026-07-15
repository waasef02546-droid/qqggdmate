from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import DataAccessRequest, PolicyDecision
from presaga.provider.token_service import TokenService


class TokenServiceTest(unittest.TestCase):
    def setUp(self):
        self.backend = ToyPRE()
        self.requester = self.backend.generate_keypair()
        self.service = TokenService(b"issuer-secret")
        self.request = DataAccessRequest(
            request_id="req-1",
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
            record_id="cal-001",
            data_class="calendar",
            data_subclass="availability",
            purpose="schedule_meeting",
            version=2,
            requester_public_key=self.requester.public_key,
        )
        self.decision = PolicyDecision(
            effect="allow",
            reason="policy_match",
            policy_id="policy-calendar-v1",
            max_uses=1,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

    def test_issues_and_validates_bound_token(self):
        token = self.service.issue_data_token(self.decision, self.request)
        validation = self.service.validate(token, self.request)
        self.assertEqual(validation.effect, "allow")
        self.assertEqual(validation.reason, "token_valid")

    def test_rejects_requester_mismatch(self):
        token = self.service.issue_data_token(self.decision, self.request)
        wrong = DataAccessRequest(**{**self.request.__dict__, "requester_aid": "mallory@mail.com:agent"})
        validation = self.service.validate(token, wrong)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "requester_mismatch")

    def test_rejects_purpose_mismatch(self):
        token = self.service.issue_data_token(self.decision, self.request)
        wrong = DataAccessRequest(**{**self.request.__dict__, "purpose": "expense_report"})
        validation = self.service.validate(token, wrong)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "purpose_mismatch")

    def test_consumes_max_uses(self):
        token = self.service.issue_data_token(self.decision, self.request)
        self.service.consume(token)
        validation = self.service.validate(token, self.request)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "token_exhausted")


if __name__ == "__main__":
    unittest.main()

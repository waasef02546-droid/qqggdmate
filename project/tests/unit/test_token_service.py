from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import DataAccessRequest, PolicyDecision
from presaga.provider.saga_adapter import SagaCompatibleAdapter
from presaga.provider.token_service import TokenService


class TokenServiceTest(unittest.TestCase):
    def setUp(self):
        self.backend = ToyPRE()
        self.requester = self.backend.generate_keypair()
        self.service = TokenService(b"issuer-secret")
        self.contact_authorizer = SagaCompatibleAdapter(b"issuer-secret")
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
        self.contact_authorizer.set_rulebook(
            self.request.owner_aid,
            [{"pattern": "bob@mail.com:*", "budget": 3}],
        )
        self.contact = self.contact_authorizer.issue_contact_token(
            owner_aid=self.request.owner_aid,
            requester_aid=self.request.requester_aid,
        )
        self.assertIsNotNone(self.contact)
        self.decision = PolicyDecision(
            effect="allow",
            reason="policy_match",
            policy_id="policy-calendar-v1",
            max_uses=1,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

    def test_issues_and_validates_bound_token(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)
        validation = self.service.validate(token, self.request, self.contact)
        self.assertEqual(validation.effect, "allow")
        self.assertEqual(validation.reason, "token_valid")
        self.assertEqual(token.contact_token_id, self.contact.token_id)
        self.assertEqual(token.contact_session_ref, self.contact.contact_session_ref)
        self.assertEqual(token.expires_at, self.contact.expires_at)

    def test_rejects_requester_mismatch(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)
        wrong = DataAccessRequest(**{**self.request.__dict__, "requester_aid": "mallory@mail.com:agent"})
        validation = self.service.validate(token, wrong, self.contact)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "requester_mismatch")

    def test_rejects_purpose_mismatch(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)
        wrong = DataAccessRequest(**{**self.request.__dict__, "purpose": "expense_report"})
        validation = self.service.validate(token, wrong, self.contact)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "purpose_mismatch")

    def test_consumes_max_uses(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)
        self.service.consume(token)
        validation = self.service.validate(token, self.request, self.contact)
        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "token_exhausted")

    def test_rejects_a_different_valid_contact_session(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)
        other_contact = self.contact_authorizer.issue_contact_token(
            owner_aid=self.request.owner_aid,
            requester_aid=self.request.requester_aid,
        )
        self.assertIsNotNone(other_contact)

        validation = self.service.validate(token, self.request, other_contact)

        self.assertEqual(validation.effect, "deny")
        self.assertEqual(validation.reason, "contact_session_mismatch")

    def test_validate_and_consume_is_atomic_under_concurrent_replay(self):
        token = self.service._issue_data_token(self.decision, self.request, self.contact)

        with ThreadPoolExecutor(max_workers=8) as executor:
            decisions = list(
                executor.map(
                    lambda _: self.service.validate_and_consume(token, self.request, self.contact),
                    range(8),
                )
            )

        self.assertEqual(sum(decision.effect == "allow" for decision in decisions), 1)
        self.assertEqual(sum(decision.reason == "token_exhausted" for decision in decisions), 7)
        self.assertEqual(token.remaining_uses, 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from experiments.baselines.saga_contact_only import run_baseline
from experiments.tasks.schedule_meeting import run_task as run_schedule_meeting
from presaga.crypto.toy_pre import ToyPRE
from presaga.provider.app import PREProviderApp
from presaga.provider.saga_adapter import SagaCompatibleAdapter, parse_aid


class P1SagaAdapterTest(unittest.TestCase):
    def test_aid_parser_requires_user_and_agent_name(self):
        parsed = parse_aid("alice@mail.com:calendar_agent")
        self.assertEqual("alice@mail.com", parsed.user_id)
        self.assertEqual("calendar_agent", parsed.agent_name)
        with self.assertRaises(ValueError):
            parse_aid("calendar_agent")
        with self.assertRaises(ValueError):
            parse_aid("alice@mail.com:")

    def test_contact_token_issue_validate_and_budget(self):
        adapter = SagaCompatibleAdapter(b"issuer-secret")
        adapter.set_rulebook("alice@mail.com:calendar_agent", [{"pattern": "bob@mail.com:*", "budget": 1}])

        token = adapter.issue_contact_token(
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
        )
        self.assertIsNotNone(token)
        self.assertEqual(0, token.remaining_budget_after_issue)

        decision = adapter.validate_contact_token(
            token,
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
        )
        self.assertEqual("allow", decision.effect)
        self.assertEqual("contact_token_valid", decision.reason)

        exhausted = adapter.issue_contact_token(
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
        )
        self.assertIsNone(exhausted)

    def test_contact_token_rejects_requester_mismatch_and_expiry(self):
        now = datetime.now(timezone.utc)
        adapter = SagaCompatibleAdapter(b"issuer-secret", contact_ttl_seconds=1)
        adapter.set_rulebook("alice@mail.com:calendar_agent", [{"pattern": "bob@mail.com:*", "budget": 2}])
        token = adapter.issue_contact_token(
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
            now=now,
        )
        self.assertIsNotNone(token)

        mismatch = adapter.validate_contact_token(
            token,
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="mallory@mail.com:tool_agent",
            now=now,
        )
        self.assertEqual("deny", mismatch.effect)
        self.assertEqual("contact_requester_mismatch", mismatch.reason)

        expired = adapter.validate_contact_token(
            token,
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
            now=now + timedelta(seconds=2),
        )
        self.assertEqual("deny", expired.effect)
        self.assertEqual("contact_token_expired", expired.reason)

    def test_provider_app_exposes_saga_contact_token_before_data_layer(self):
        backend = ToyPRE()
        app = PREProviderApp(backend)
        owner = backend.generate_keypair()
        requester = backend.generate_keypair()
        app.management.register_agent("alice@mail.com:calendar_agent", owner.public_key)
        app.management.register_agent("bob@mail.com:scheduler_agent", requester.public_key)
        app.management.set_contact_rulebook("alice@mail.com:calendar_agent", [{"pattern": "bob@mail.com:*", "budget": 1}])

        token = app.issue_contact_session("alice@mail.com:calendar_agent", "bob@mail.com:scheduler_agent")
        self.assertIsNotNone(token)
        decision = app.validate_contact_session(
            token,
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
        )
        self.assertEqual("allow", decision.effect)

    def test_schedule_meeting_task_uses_contact_token_path(self):
        result = run_schedule_meeting()
        self.assertTrue(result.success)
        self.assertEqual("task_completed", result.reason)

    def test_saga_contact_only_baseline_uses_adapter_token(self):
        result = run_baseline()
        self.assertTrue(result.contact_allowed)
        self.assertTrue(result.contact_session_ref.startswith("contact-"))
        self.assertEqual(0, result.remaining_budget_after_issue)


if __name__ == "__main__":
    unittest.main()

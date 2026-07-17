from __future__ import annotations

import unittest

from experiments.attacks.purpose_mismatch import run_attack as run_purpose_mismatch
from experiments.attacks.requester_mismatch import run_attack as run_requester_mismatch
from experiments.attacks.token_reuse import run_attack as run_token_reuse
from experiments.attacks.unauthorized_data_class import run_attack as run_unauthorized_data_class


class AttackScriptTest(unittest.TestCase):
    def test_stage3_attacks_are_blocked_after_contact_is_allowed(self):
        results = [
            run_unauthorized_data_class(),
            run_purpose_mismatch(),
            run_token_reuse(),
            run_requester_mismatch(),
        ]
        self.assertEqual(4, len(results))
        for result in results:
            with self.subTest(result.attack):
                self.assertTrue(result.baseline_contact_allowed)
                self.assertTrue(result.expected_blocked)
                self.assertTrue(result.blocked)
                self.assertTrue(result.success)
                self.assertTrue(result.audit_id.startswith("audit-"))


if __name__ == "__main__":
    unittest.main()

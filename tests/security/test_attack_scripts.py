from __future__ import annotations

import unittest

from experiments.attacks.compromised_requester_exfiltration import run_attack as run_compromised_requester_exfiltration
from experiments.attacks.metadata_linkage_probe import run_attack as run_metadata_linkage_probe
from experiments.attacks.purpose_mismatch import run_attack as run_purpose_mismatch
from experiments.attacks.provider_plaintext_probe import run_attack as run_provider_plaintext_probe
from experiments.attacks.requester_mismatch import run_attack as run_requester_mismatch
from experiments.attacks.run_all import run_all
from experiments.attacks.stale_rekey_use import run_attack as run_stale_rekey_use
from experiments.attacks.token_reuse import run_attack as run_token_reuse
from experiments.attacks.unauthorized_data_class import run_attack as run_unauthorized_data_class


class AttackScriptTest(unittest.TestCase):
    def test_stage3_attacks_are_blocked_after_contact_is_allowed(self):
        results = [
            run_unauthorized_data_class(),
            run_purpose_mismatch(),
            run_token_reuse(),
            run_requester_mismatch(),
            run_stale_rekey_use(),
            run_provider_plaintext_probe(),
            run_metadata_linkage_probe(),
            run_compromised_requester_exfiltration(),
        ]
        self.assertEqual(8, len(results))
        for result in results:
            with self.subTest(result.attack):
                self.assertTrue(result.baseline_contact_allowed)
                self.assertTrue(result.expected_blocked)
                self.assertTrue(result.blocked)
                self.assertTrue(result.success)
                self.assertTrue(result.audit_id.startswith("audit-"))

    def test_security_matrix_contains_stage_p2_attacks(self):
        results, output_path = run_all()
        attack_names = {result.attack for result in results}
        self.assertTrue(output_path.exists())
        self.assertEqual(
            {
                "unauthorized_data_class",
                "purpose_mismatch",
                "token_reuse",
                "requester_mismatch",
                "stale_rekey_use",
                "provider_plaintext_probe",
                "metadata_linkage_probe",
                "compromised_requester_exfiltration",
            },
            attack_names,
        )


if __name__ == "__main__":
    unittest.main()

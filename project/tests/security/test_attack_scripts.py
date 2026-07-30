from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.attacks.compromised_requester_exfiltration import run_attack as run_compromised_requester_exfiltration
from experiments.attacks.common import (
    allowed_request,
    issue_allowed_token,
    make_environment,
    rekey_for_requester,
)
from experiments.attacks.metadata_linkage_probe import run_attack as run_metadata_linkage_probe
from experiments.attacks.purpose_mismatch import run_attack as run_purpose_mismatch
from experiments.attacks.provider_plaintext_probe import run_attack as run_provider_plaintext_probe
from experiments.attacks.requester_mismatch import run_attack as run_requester_mismatch
from experiments.attacks.run_all import run_all
from experiments.attacks.stale_rekey_use import run_attack as run_stale_rekey_use
from experiments.attacks.token_reuse import run_attack as run_token_reuse
from experiments.attacks.unauthorized_data_class import run_attack as run_unauthorized_data_class


class AttackScriptTest(unittest.TestCase):
    def test_invalid_umbral_rekey_is_audited_and_does_not_consume_token(self):
        env = make_environment()
        request = allowed_request(env)
        token = issue_allowed_token(env)

        denied = env.provider.request_re_encryption(token, request, b"malformed")
        self.assertEqual("deny", denied.decision)
        self.assertEqual("crypto_artifact_invalid", denied.reason)
        self.assertTrue(denied.audit_id.startswith("audit-"))
        self.assertEqual(1, token.remaining_uses)

        allowed = env.provider.request_re_encryption(
            token,
            request,
            rekey_for_requester(env),
        )
        self.assertEqual("allow", allowed.decision)
        self.assertIsNotNone(allowed.transformed_encrypted_dek)
        self.assertEqual(0, token.remaining_uses)

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
                self.assertTrue(result.success)
                self.assertTrue(result.audit_id.startswith("audit-"))
        blocking_attacks = [
            result for result in results if result.expected_blocked
        ]
        limitation_probes = [
            result for result in results if not result.expected_blocked
        ]
        self.assertEqual(8, len(blocking_attacks))
        self.assertTrue(all(result.blocked for result in blocking_attacks))
        self.assertEqual(0, len(limitation_probes))
        provider_probe = next(
            result
            for result in results
            if result.attack == "provider_plaintext_probe"
        )
        self.assertEqual(
            "provider_public_material_recovery_blocked",
            provider_probe.reason,
        )

    def test_security_matrix_contains_stage_p2_attacks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results, output_path = run_all(
                Path(temp_dir) / "security_matrix.csv"
            )
            self.assertTrue(output_path.exists())
        attack_names = {result.attack for result in results}
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

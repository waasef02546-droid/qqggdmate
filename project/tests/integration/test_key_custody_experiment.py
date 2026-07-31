from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from experiments.e2e.key_custody import run_key_custody_probe


class KeyCustodyExperimentTest(unittest.TestCase):
    def test_probe_closes_rotation_and_writes_one_success_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            result = run_key_custody_probe(output_root)

            self.assertTrue(result.signed_artifact_verified)
            self.assertEqual(1, result.custody_version)
            self.assertTrue(result.custody_key_id_matches_authoritative_source)
            self.assertTrue(result.owner_approval_required)
            self.assertTrue(result.unapproved_target_rejected)
            self.assertEqual(
                "custody_request_not_approved",
                result.unapproved_target_reason,
            )
            self.assertTrue(result.exact_retry_idempotent)
            self.assertTrue(result.conflicting_retry_rejected)
            self.assertEqual("custody_artifact_conflict", result.conflicting_retry_reason)
            self.assertTrue(result.legacy_private_key_input_rejected)
            self.assertEqual("source_private_key_forbidden", result.legacy_rejection_reason)
            self.assertTrue(result.target_decrypt_succeeded)
            self.assertFalse(result.provider_received_source_private_key)
            self.assertFalse(result.provider_saw_plaintext_dek)
            self.assertTrue(result.success)
            self.assertIn("Prototype process-boundary", result.limitation)

            csv_path = output_root / "tables" / "key_custody_summary.csv"
            self.assertTrue(csv_path.is_file())
            with csv_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(1, len(rows))
            row = rows[0]
            expected_boolean_text = {
                "signed_artifact_verified": "True",
                "custody_key_id_matches_authoritative_source": "True",
                "owner_approval_required": "True",
                "unapproved_target_rejected": "True",
                "exact_retry_idempotent": "True",
                "conflicting_retry_rejected": "True",
                "legacy_private_key_input_rejected": "True",
                "target_decrypt_succeeded": "True",
                "provider_received_source_private_key": "False",
                "provider_saw_plaintext_dek": "False",
                "success": "True",
            }
            for field, expected in expected_boolean_text.items():
                with self.subTest(field=field):
                    self.assertEqual(expected, row[field])


if __name__ == "__main__":
    unittest.main()

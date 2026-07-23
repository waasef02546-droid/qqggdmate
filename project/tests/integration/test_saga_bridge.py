from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.e2e.saga_bridge import load_saga_baseline_evidence, run_saga_bridge


class SagaBridgeIntegrationTest(unittest.TestCase):
    def test_importer_reads_recorded_saga_evidence(self):
        evidence = load_saga_baseline_evidence()
        self.assertEqual({"saga_e2e_alice_bob", "saga_multi_agent_alice_bob_mallory"}, {item.case for item in evidence})
        self.assertTrue(all(Path(item.evidence_path).is_file() for item in evidence))
        self.assertTrue(all(item.contact_authorized and item.token_lifecycle_observed for item in evidence))

    def test_bridge_outputs_normal_allow_and_contact_allowed_data_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            results = run_saga_bridge(output_root=Path(directory))
            by_case = {result.case: result for result in results}
            allowed = by_case["alice_bob_authorized_calendar"]
            denied = by_case["alice_mallory_contact_allowed_data_denied"]
            self.assertTrue(allowed.saga_contact_allowed)
            self.assertTrue(allowed.presaga_data_allowed)
            self.assertTrue(allowed.plaintext_released)
            self.assertTrue(denied.saga_contact_allowed)
            self.assertFalse(denied.presaga_data_allowed)
            self.assertEqual("deny", denied.data_layer_decision)
            self.assertFalse(denied.plaintext_released)
            self.assertTrue((Path(directory) / "tables" / "saga_bridge_summary.csv").is_file())
            self.assertTrue((Path(directory) / "saga_bridge_report.md").is_file())


if __name__ == "__main__":
    unittest.main()

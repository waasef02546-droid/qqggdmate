from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from proofs.run_proverif import PROOF_FILES, run_proofs


class ProVerifRunnerTest(unittest.TestCase):
    def test_runner_records_every_proof_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            results = run_proofs(output_root=output_root)
            self.assertEqual(set(PROOF_FILES), {result.proof for result in results})
            for result in results:
                self.assertTrue(result.output_path.exists(), result.output_path)
                self.assertIn(result.status, {"passed", "failed", "tool_unavailable"})
                self.assertTrue(result.contribution)

            summary = output_root / "proverif_summary.csv"
            report = output_root / "proverif_report.md"
            self.assertTrue(summary.exists())
            self.assertTrue(report.exists())
            with summary.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(PROOF_FILES), len(rows))
            self.assertTrue(all(row["proof"] in PROOF_FILES for row in rows))
            self.assertIn("P1", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

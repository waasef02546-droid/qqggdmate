from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from experiments.performance.run_performance import run_performance


class PerformanceRunnerTest(unittest.TestCase):
    def test_performance_runner_generates_tables_and_figures(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rows = run_performance(root)
            self.assertGreaterEqual(len(rows), 9)
            performance = root / "tables" / "performance.csv"
            scalability = root / "tables" / "scalability_policy_rules.csv"
            latency_svg = root / "figures" / "latency_breakdown.svg"
            scalability_svg = root / "figures" / "scalability_policy_rules.svg"
            self.assertTrue(performance.exists())
            self.assertTrue(scalability.exists())
            self.assertTrue(latency_svg.exists())
            self.assertTrue(scalability_svg.exists())
            with performance.open(encoding="utf-8") as handle:
                csv_rows = list(csv.DictReader(handle))
            baselines = {row["baseline"] for row in csv_rows}
            self.assertIn("saga_contact_only", baselines)
            self.assertIn("plaintext_token_server", baselines)
            self.assertIn("presaga", baselines)


if __name__ == "__main__":
    unittest.main()

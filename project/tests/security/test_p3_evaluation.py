from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from experiments.evaluation.run_p3_evaluation import run_p3_evaluation, run_task_scalability


class P3EvaluationTest(unittest.TestCase):
    def test_p3_evaluation_generates_task_level_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            outputs = run_p3_evaluation(root)

            self.assertEqual("4/4", outputs.task_success_rate)
            self.assertEqual(9, outputs.scalability_rows)
            for path in (
                outputs.task_summary_path,
                outputs.denial_summary_path,
                outputs.task_latency_breakdown_path,
                outputs.task_scalability_path,
                outputs.task_latency_figure_path,
                outputs.task_scalability_figure_path,
            ):
                self.assertTrue(path.exists(), path)

            with outputs.task_summary_path.open(encoding="utf-8") as handle:
                summary = {row["metric"]: row["value"] for row in csv.DictReader(handle)}
            self.assertEqual("4/4", summary["task_success_rate"])

            with outputs.denial_summary_path.open(encoding="utf-8") as handle:
                denial_reasons = {row["reason"] for row in csv.DictReader(handle)}
            self.assertIn("purpose_mismatch", denial_reasons)
            self.assertIn("record_scope_denied", denial_reasons)

            with outputs.task_latency_breakdown_path.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(4, len(rows))
            self.assertTrue(all("pre_transform_ms" in row for row in rows))

    def test_task_scalability_covers_agents_policies_and_records(self):
        rows = run_task_scalability(iterations=2)
        dimensions = {row.dimension for row in rows}
        self.assertEqual({"agent_count", "policy_count", "record_count"}, dimensions)
        self.assertTrue(all(row.success_rate == 1.0 for row in rows))


if __name__ == "__main__":
    unittest.main()

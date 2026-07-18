"""Run all task-level PRE-SAGA experiments."""

from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path

from experiments.tasks.collaborative_writing import run_task as run_collaborative_writing
from experiments.tasks.cross_agent_memory_query import run_task as run_cross_agent_memory_query
from experiments.tasks.expense_report import run_task as run_expense_report
from experiments.tasks.schedule_meeting import run_task as run_schedule_meeting


def run_all(output_path: Path = Path("results") / "tables" / "task_results.csv"):
    results = [
        run_schedule_meeting(),
        run_expense_report(),
        run_collaborative_writing(),
        run_cross_agent_memory_query(),
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))
    return results, output_path


if __name__ == "__main__":
    results, path = run_all()
    for result in results:
        print(result)
    print(f"task_results={path}")

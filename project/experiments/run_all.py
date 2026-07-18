"""Run all currently implemented PRE-SAGA experiments."""

from __future__ import annotations

from experiments.attacks.run_all import run_all as run_attacks
from experiments.tasks.run_all import run_all as run_tasks
from experiments.performance.run_performance import run_performance


if __name__ == "__main__":
    results, output_path = run_attacks()
    task_results, task_output_path = run_tasks()
    performance_rows = run_performance()
    blocked = sum(1 for result in results if result.blocked)
    total = len(results)
    task_success = sum(1 for result in task_results if result.success)
    print(f"attack_blocking_rate={blocked}/{total}")
    print(f"security_matrix={output_path}")
    print(f"task_success_rate={task_success}/{len(task_results)}")
    print(f"task_results={task_output_path}")
    print(f"performance_rows={len(performance_rows)}")
    print("performance=results\\tables\\performance.csv")

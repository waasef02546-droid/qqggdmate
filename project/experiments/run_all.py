"""Run all currently implemented PRE-SAGA experiments."""

from __future__ import annotations

from experiments.attacks.run_all import run_all as run_attacks
from experiments.evaluation.run_p3_evaluation import run_p3_evaluation
from experiments.tasks.run_all import run_all as run_tasks
from experiments.performance.run_performance import run_performance
from proofs.run_proverif import run_proofs


if __name__ == "__main__":
    results, output_path = run_attacks()
    task_results, task_output_path = run_tasks()
    performance_rows = run_performance()
    p3_outputs = run_p3_evaluation(task_results=task_results, attack_results=results)
    proof_results = run_proofs()
    blocked = sum(1 for result in results if result.blocked)
    total = len(results)
    task_success = sum(1 for result in task_results if result.success)
    proof_statuses = ",".join(f"{result.proof}:{result.status}" for result in proof_results)
    print(f"attack_blocking_rate={blocked}/{total}")
    print(f"security_matrix={output_path}")
    print(f"task_success_rate={task_success}/{len(task_results)}")
    print(f"task_results={task_output_path}")
    print(f"performance_rows={len(performance_rows)}")
    print("performance=results\\tables\\performance.csv")
    print(f"p3_task_summary={p3_outputs.task_summary_path}")
    print(f"p3_task_scalability_rows={p3_outputs.scalability_rows}")
    print(f"proof_statuses={proof_statuses}")

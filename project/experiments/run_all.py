"""Run all currently implemented PRE-SAGA experiments."""

from __future__ import annotations

from experiments.attacks.run_all import run_all as run_attacks
from experiments.performance.run_performance import run_performance


if __name__ == "__main__":
    results, output_path = run_attacks()
    performance_rows = run_performance()
    blocked = sum(1 for result in results if result.blocked)
    total = len(results)
    print(f"attack_blocking_rate={blocked}/{total}")
    print(f"security_matrix={output_path}")
    print(f"performance_rows={len(performance_rows)}")
    print("performance=results\\tables\\performance.csv")

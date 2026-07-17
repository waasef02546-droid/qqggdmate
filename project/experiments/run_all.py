"""Run all currently implemented PRE-SAGA experiments."""

from __future__ import annotations

from experiments.attacks.run_all import run_all as run_attacks


if __name__ == "__main__":
    results, output_path = run_attacks()
    blocked = sum(1 for result in results if result.blocked)
    total = len(results)
    print(f"attack_blocking_rate={blocked}/{total}")
    print(f"security_matrix={output_path}")

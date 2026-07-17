"""Run PRE-SAGA stage 3 attack experiments and emit security_matrix.csv."""

from __future__ import annotations

from pathlib import Path

from experiments.attacks.purpose_mismatch import run_attack as run_purpose_mismatch
from experiments.attacks.requester_mismatch import run_attack as run_requester_mismatch
from experiments.attacks.token_reuse import run_attack as run_token_reuse
from experiments.attacks.unauthorized_data_class import run_attack as run_unauthorized_data_class
from experiments.attacks.common import write_security_matrix


def run_all():
    results = [
        run_unauthorized_data_class(),
        run_purpose_mismatch(),
        run_token_reuse(),
        run_requester_mismatch(),
    ]
    output_path = Path("results") / "tables" / "security_matrix.csv"
    write_security_matrix(results, output_path)
    return results, output_path


if __name__ == "__main__":
    results, output_path = run_all()
    for result in results:
        print(result.to_json())
    print(f"security_matrix={output_path}")

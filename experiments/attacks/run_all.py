"""Run PRE-SAGA stage 3 attack experiments and emit security_matrix.csv."""

from __future__ import annotations

from pathlib import Path

from experiments.attacks.compromised_requester_exfiltration import run_attack as run_compromised_requester_exfiltration
from experiments.attacks.metadata_linkage_probe import run_attack as run_metadata_linkage_probe
from experiments.attacks.purpose_mismatch import run_attack as run_purpose_mismatch
from experiments.attacks.provider_plaintext_probe import run_attack as run_provider_plaintext_probe
from experiments.attacks.requester_mismatch import run_attack as run_requester_mismatch
from experiments.attacks.stale_rekey_use import run_attack as run_stale_rekey_use
from experiments.attacks.token_reuse import run_attack as run_token_reuse
from experiments.attacks.unauthorized_data_class import run_attack as run_unauthorized_data_class
from experiments.attacks.common import write_security_matrix


def run_all():
    results = [
        run_unauthorized_data_class(),
        run_purpose_mismatch(),
        run_token_reuse(),
        run_requester_mismatch(),
        run_stale_rekey_use(),
        run_provider_plaintext_probe(),
        run_metadata_linkage_probe(),
        run_compromised_requester_exfiltration(),
    ]
    output_path = Path("results") / "tables" / "security_matrix.csv"
    write_security_matrix(results, output_path)
    return results, output_path


if __name__ == "__main__":
    results, output_path = run_all()
    for result in results:
        print(result.to_json())
    print(f"security_matrix={output_path}")

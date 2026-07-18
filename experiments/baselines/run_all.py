"""Run all baseline comparisons."""

from __future__ import annotations

from experiments.baselines.presaga import run_baseline as run_presaga
from experiments.baselines.saga_contact_only import run_baseline as run_saga_contact_only
from experiments.baselines.token_plaintext_server import run_baseline as run_token_plaintext_server


def run_all():
    return [run_saga_contact_only(), run_token_plaintext_server(), run_presaga()]


if __name__ == "__main__":
    for result in run_all():
        print(result)

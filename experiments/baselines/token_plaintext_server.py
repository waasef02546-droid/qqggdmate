"""Baseline: server-side token check followed by plaintext return."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.attacks.common import allowed_request, make_environment
from presaga.provider.data_policy import DataPolicyEvaluator


@dataclass(frozen=True)
class PlaintextBaselineResult:
    baseline: str
    success: bool
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    reason: str
    plaintext: str


def run_baseline() -> PlaintextBaselineResult:
    env = make_environment(max_uses=1)
    request = allowed_request(env)
    decision = DataPolicyEvaluator([env.policy]).evaluate(request)
    if decision.effect != "allow":
        return PlaintextBaselineResult("token_plaintext_server", False, False, False, decision.reason, "")
    dek = env.backend.unwrap_dek(env.stored.encrypted_dek_owner, env.owner_keypair.private_key, env.store.context(env.stored.record))
    plaintext = env.store.decrypt_with_dek(env.stored, dek).decode("utf-8")
    return PlaintextBaselineResult("token_plaintext_server", True, True, True, "policy_match", plaintext)


if __name__ == "__main__":
    print(run_baseline())

"""Baseline: PRE-SAGA data authorization and encrypted DEK transform."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.attacks.common import allowed_request, issue_allowed_token, make_environment, rekey_for_requester


@dataclass(frozen=True)
class PRESAGABaselineResult:
    baseline: str
    success: bool
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    reason: str


def run_baseline() -> PRESAGABaselineResult:
    env = make_environment(max_uses=1)
    request = allowed_request(env)
    token = issue_allowed_token(env)
    result = env.proxy.transform(
        token=token,
        request=request,
        encrypted_dek_owner=env.stored.encrypted_dek_owner,
        rekey=rekey_for_requester(env),
    )
    return PRESAGABaselineResult(
        baseline="presaga",
        success=result.decision == "allow",
        provider_plaintext_data_visible=False,
        provider_plaintext_dek_visible=False,
        reason=result.reason,
    )


if __name__ == "__main__":
    print(run_baseline())

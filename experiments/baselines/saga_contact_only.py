"""Baseline: SAGA-style contact authorization without data authorization."""

from __future__ import annotations

from dataclasses import dataclass

from presaga.provider.contact_policy import SAGAStyleContactPolicy


@dataclass(frozen=True)
class BaselineResult:
    baseline: str
    contact_allowed: bool
    data_layer_control: bool
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    reason: str


def run_baseline() -> BaselineResult:
    policy = SAGAStyleContactPolicy([{"pattern": "bob@mail.com:scheduler_agent", "budget": 1}])
    decision = policy.evaluate("bob@mail.com:scheduler_agent")
    return BaselineResult(
        baseline="saga_contact_only",
        contact_allowed=decision.effect == "allow",
        data_layer_control=False,
        provider_plaintext_data_visible=False,
        provider_plaintext_dek_visible=False,
        reason=decision.reason,
    )


if __name__ == "__main__":
    print(run_baseline())

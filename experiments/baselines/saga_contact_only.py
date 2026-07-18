"""Baseline: SAGA-compatible contact authorization without data authorization."""

from __future__ import annotations

from dataclasses import dataclass

from presaga.provider.saga_adapter import SagaCompatibleAdapter


@dataclass(frozen=True)
class BaselineResult:
    baseline: str
    contact_allowed: bool
    contact_session_ref: str
    remaining_budget_after_issue: int | None
    data_layer_control: bool
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    reason: str


def run_baseline() -> BaselineResult:
    adapter = SagaCompatibleAdapter(b"baseline-issuer")
    adapter.set_rulebook("alice@mail.com:calendar_agent", [{"pattern": "bob@mail.com:scheduler_agent", "budget": 1}])
    token = adapter.issue_contact_token(
        owner_aid="alice@mail.com:calendar_agent",
        requester_aid="bob@mail.com:scheduler_agent",
    )
    decision = (
        adapter.validate_contact_token(
            token,
            owner_aid="alice@mail.com:calendar_agent",
            requester_aid="bob@mail.com:scheduler_agent",
        )
        if token
        else None
    )
    return BaselineResult(
        baseline="saga_contact_only",
        contact_allowed=decision is not None and decision.effect == "allow",
        contact_session_ref=token.contact_session_ref if token else "",
        remaining_budget_after_issue=token.remaining_budget_after_issue if token else None,
        data_layer_control=False,
        provider_plaintext_data_visible=False,
        provider_plaintext_dek_visible=False,
        reason=decision.reason if decision else "contact_denied",
    )


if __name__ == "__main__":
    print(run_baseline())

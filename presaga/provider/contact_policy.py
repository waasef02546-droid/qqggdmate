"""SAGA-style contact policy gate.

This module intentionally models only the part of SAGA that PRE-SAGA needs as a
baseline prerequisite: whether a requester agent may contact an owner agent.
Data decryption authorization is deliberately handled later by Data Sharing
Policy and data tokens.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch


@dataclass(frozen=True)
class ContactDecision:
    effect: str
    reason: str
    matched_pattern: str | None = None
    remaining_budget: int | None = None


class SAGAStyleContactPolicy:
    """Small local model of SAGA's contact rulebook semantics.

    A rule with a positive budget allows contact and consumes one budget unit.
    A matched rule with zero or negative budget denies contact. The policy only
    decides contact permission; it does not grant data decryption rights.
    """

    def __init__(self, rulebook: list[dict[str, int | str]]):
        self.rulebook = [dict(rule) for rule in rulebook]

    def evaluate(self, requester_aid: str, *, consume: bool = True) -> ContactDecision:
        for rule in self.rulebook:
            pattern = str(rule["pattern"])
            budget = int(rule["budget"])
            if not fnmatch(requester_aid, pattern):
                continue
            if budget <= 0:
                return ContactDecision("deny", "contact_budget_exhausted", pattern, budget)
            if consume:
                budget -= 1
                rule["budget"] = budget
            return ContactDecision("allow", "contact_allowed", pattern, budget)
        return ContactDecision("deny", "contact_policy_not_matched")


def contact_allowed(rulebook: list[dict[str, int | str]], requester_aid: str) -> bool:
    return SAGAStyleContactPolicy(rulebook).evaluate(requester_aid, consume=False).effect == "allow"

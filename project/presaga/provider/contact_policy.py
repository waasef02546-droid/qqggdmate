"""Minimal SAGA-style contact policy placeholder."""

from __future__ import annotations

from fnmatch import fnmatch


def contact_allowed(rulebook: list[dict[str, int | str]], requester_aid: str) -> bool:
    for rule in rulebook:
        pattern = str(rule["pattern"])
        budget = int(rule["budget"])
        if fnmatch(requester_aid, pattern):
            return budget > 0
    return False

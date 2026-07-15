"""Validation helpers."""

from __future__ import annotations


def require_aid(value: str, field_name: str) -> None:
    if ":" not in value or "@" not in value.split(":", 1)[0]:
        raise ValueError(f"{field_name} must be an agent id like user@example.com:agent")


def require_non_empty(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must not be empty")

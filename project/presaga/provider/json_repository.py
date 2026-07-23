"""Small file-backed persistence for the standalone Provider service.

This repository is deliberately dependency-free.  It provides a local
development backend while the existing Mongo repository remains available for
the separate MongoDB experiment.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


class JsonProviderRepository:
    """Persist Provider state atomically in one JSON document."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.empty_state()
        with self.path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        return {**self.empty_state(), **state}

    def save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(to_jsonable(state), handle, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(temporary, self.path)

    @staticmethod
    def empty_state() -> dict[str, Any]:
        return {
            "agents": [],
            "contact_rulebooks": {},
            "data_policies": [],
            "contact_tokens": [],
            "data_tokens": [],
            "audit_events": [],
        }


def to_jsonable(value: Any) -> Any:
    """Convert protocol dataclasses and binary values to JSON-safe objects."""
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return {"__bytes_b64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def from_b64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


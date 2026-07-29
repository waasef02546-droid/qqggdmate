"""Small file-backed persistence for the standalone Provider service.

This repository is deliberately dependency-free.  It provides a local
development backend while the existing Mongo repository remains available for
the separate MongoDB experiment.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from threading import RLock

from presaga.provider.repository import RepositoryConflict


class JsonProviderRepository:
    """Persist Provider state atomically in one JSON document."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = RLock()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.empty_state()
        with self.path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if not isinstance(state, dict):
            raise ValueError("provider state must be an object")
        schema_version = int(state.get("schema_version", 1))
        if schema_version > 3:
            raise ValueError("provider state schema is newer than this implementation")
        state_revision = int(state.get("state_revision", 0))
        if state_revision < 0:
            raise ValueError("provider state revision must be non-negative")
        return {
            **self.empty_state(),
            **state,
            "schema_version": schema_version,
            "state_revision": state_revision,
        }

    def save(
        self,
        state: dict[str, Any],
        *,
        expected_revision: int | None = None,
    ) -> int:
        with self._lock:
            current_revision = (
                int(self.load().get("state_revision", 0))
                if self.path.exists()
                else 0
            )
            expected = (
                int(state.get("state_revision", current_revision))
                if expected_revision is None
                else expected_revision
            )
            if expected != current_revision:
                raise RepositoryConflict()
            next_revision = current_revision + 1
            persisted = {**state, "state_revision": next_revision}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + f".{secrets.token_hex(6)}.tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(
                    to_jsonable(persisted),
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            return next_revision

    @staticmethod
    def empty_state() -> dict[str, Any]:
        return {
            "schema_version": 3,
            "state_revision": 0,
            "agents": [],
            "contact_rulebooks": {},
            "data_policies": [],
            "contact_tokens": [],
            "data_tokens": [],
            "audit_events": [],
            "rotation_journal": [],
            "encrypted_objects": [],
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

"""Persistence boundary for recoverable PRE-SAGA Provider state."""

from __future__ import annotations

from typing import Any, Protocol


class RepositoryError(RuntimeError):
    """Stable persistence-layer failure exposed by the service boundary."""

    reason = "repository_unavailable"

    def __init__(self, reason: str | None = None) -> None:
        super().__init__(reason or self.reason)
        self.reason = reason or self.reason


class RepositoryConflict(RepositoryError):
    """A stale Provider attempted to overwrite a newer persisted revision."""

    reason = "repository_state_conflict"

    def __init__(self) -> None:
        super().__init__(self.reason)


class RepositoryUnavailable(RepositoryError):
    """Provider state is uncertain; restart/recovery is required."""

    reason = "repository_recovery_required"


class ProviderRepository(Protocol):
    """Atomic aggregate-state persistence used by ``ProviderService``."""

    def load(self) -> dict[str, Any]:
        """Load one validated aggregate containing ``state_revision``."""
        ...

    def save(
        self,
        state: dict[str, Any],
        *,
        expected_revision: int,
    ) -> int:
        """Persist exactly ``expected_revision + 1`` or raise conflict."""
        ...

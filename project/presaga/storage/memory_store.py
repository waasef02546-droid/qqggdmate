"""Policy-aware cross-agent memory storage."""

from presaga.storage.policy_aware_store import PolicyAwareStore


class MemoryStore(PolicyAwareStore):
    data_class = "memory"


__all__ = ["MemoryStore"]

"""Policy-aware document tool storage."""

from presaga.storage.policy_aware_store import PolicyAwareStore


class DocumentStore(PolicyAwareStore):
    data_class = "document"


__all__ = ["DocumentStore"]

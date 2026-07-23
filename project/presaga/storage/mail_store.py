"""Policy-aware mail tool storage."""

from presaga.storage.policy_aware_store import PolicyAwareStore


class MailStore(PolicyAwareStore):
    data_class = "mail"


__all__ = ["MailStore"]

"""Policy-aware calendar tool storage."""

from presaga.storage.policy_aware_store import PolicyAwareStore


class CalendarStore(PolicyAwareStore):
    data_class = "calendar"


__all__ = ["CalendarStore"]

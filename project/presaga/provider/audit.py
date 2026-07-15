"""In-memory audit logger."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from presaga.protocol.schemas import AuditEvent


class AuditLogger:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def record(
        self,
        *,
        event_type: str,
        decision: str,
        reason: str,
        owner_aid: str,
        requester_aid: str,
        record_id: str,
        data_class: str,
        purpose: str,
        policy_id: str | None,
        token_id: str | None,
        provider_saw_plaintext_dek: bool = False,
        provider_saw_plaintext_data: bool = False,
    ) -> AuditEvent:
        event = AuditEvent(
            audit_id=f"audit-{secrets.token_hex(8)}",
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            decision=decision,  # type: ignore[arg-type]
            reason=reason,
            owner_aid=owner_aid,
            requester_aid=requester_aid,
            record_id=record_id,
            data_class=data_class,
            purpose=purpose,
            policy_id=policy_id,
            token_id=token_id,
            provider_saw_plaintext_dek=provider_saw_plaintext_dek,
            provider_saw_plaintext_data=provider_saw_plaintext_data,
        )
        self.events.append(event)
        return event

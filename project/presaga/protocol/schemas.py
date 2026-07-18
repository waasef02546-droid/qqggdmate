"""Dataclass schemas for the PRE-SAGA prototype."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


DecisionEffect = Literal["allow", "deny"]


@dataclass(frozen=True)
class RequesterSelector:
    type: Literal["aid_exact", "aid_pattern"]
    value: str


@dataclass(frozen=True)
class DataScope:
    data_classes: list[str]
    data_subclasses: list[str]
    record_ids: list[str] = field(default_factory=list)
    record_prefixes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Validity:
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class Limits:
    max_uses: int
    max_records: int = 1
    allow_bulk_export: bool = False


@dataclass(frozen=True)
class VersionConstraints:
    min_version: int
    max_version: int


@dataclass(frozen=True)
class DataSharingPolicy:
    policy_id: str
    owner_aid: str
    requester_selector: RequesterSelector
    data_scope: DataScope
    purposes: list[str]
    validity: Validity
    limits: Limits
    version_constraints: VersionConstraints
    effect: DecisionEffect = "allow"
    obligations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DataRecord:
    record_id: str
    owner_aid: str
    data_class: str
    data_subclass: str
    version: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DataAccessRequest:
    request_id: str
    owner_aid: str
    requester_aid: str
    record_id: str
    data_class: str
    data_subclass: str
    purpose: str
    version: int
    requester_public_key: bytes
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class PolicyDecision:
    effect: DecisionEffect
    reason: str
    policy_id: str | None = None
    max_uses: int = 0
    expires_at: datetime | None = None
    obligations: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataToken:
    token_id: str
    owner_aid: str
    requester_aid: str
    policy_id: str
    allowed_record_ids: list[str]
    allowed_data_classes: list[str]
    allowed_data_subclasses: list[str]
    purpose: str
    not_before: datetime
    expires_at: datetime
    max_uses: int
    remaining_uses: int
    min_version: int
    max_version: int
    requester_public_key_hash: str
    issuer_signature: str


@dataclass
class ContactToken:
    token_id: str
    owner_aid: str
    requester_aid: str
    contact_session_ref: str
    matched_pattern: str
    not_before: datetime
    expires_at: datetime
    remaining_budget_after_issue: int | None
    issuer_signature: str


@dataclass(frozen=True)
class TokenDecision:
    effect: DecisionEffect
    reason: str


@dataclass(frozen=True)
class AuditEvent:
    audit_id: str
    timestamp: datetime
    event_type: str
    decision: DecisionEffect
    reason: str
    owner_aid: str
    requester_aid: str
    record_id: str
    data_class: str
    purpose: str
    policy_id: str | None
    token_id: str | None
    provider_saw_plaintext_dek: bool
    provider_saw_plaintext_data: bool

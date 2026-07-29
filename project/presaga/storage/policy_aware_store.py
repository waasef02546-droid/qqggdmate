"""Policy-aware encrypted stores for agent-facing data tools.

The provider remains responsible for issuing data tokens.  This layer is the
last-mile enforcement point that turns a successful policy decision into a
minimal, field-projected result for a concrete mail, calendar, document, or
memory tool.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.registry import AgentRegistry
from presaga.storage.encrypted_store import EncryptedStore, StoredObject


class DataAccessDenied(PermissionError):
    """Raised when a tool request is outside its locally enforced grant."""


@dataclass(frozen=True)
class DataAccessGrant:
    """Narrow, tool-local view of an already approved data access request."""

    grant_id: str
    requester_aid: str
    purpose: str
    data_class: str
    record_scope: frozenset[str]
    allowed_fields: frozenset[str]


class PolicyAwareStore(EncryptedStore):
    """Encrypted store with record filtering and field-level projection.

    A grant is created only after the caller has obtained a matching provider
    decision/data token.  Reads must present that grant, so every data-tool
    access checks requester identity, purpose, data class, record scope, and
    requested fields before returning decrypted data.
    """

    data_class: str = "generic"

    def __init__(self, backend: PREBackend, registry: AgentRegistry):
        super().__init__(
            backend,
            registry,
            store_id=f"policy-store:{self.data_class}",
        )
        self._grants: dict[str, DataAccessGrant] = {}
        self._record_purposes: dict[str, frozenset[str]] = {}

    def put_payload(
        self,
        record: DataRecord,
        payload: Mapping[str, Any],
        *,
        purposes: Iterable[str],
    ) -> StoredObject:
        self._validate_record_class(record)
        allowed_purposes = frozenset(purposes)
        if not allowed_purposes:
            raise ValueError("purposes must contain at least one declared purpose")
        plaintext = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
        stored = self.put(record, plaintext)
        self._record_purposes[record.record_id] = allowed_purposes
        return stored

    def grant_access(
        self,
        *,
        requester_aid: str,
        purpose: str,
        data_class: str,
        record_scope: Iterable[str],
        allowed_fields: Iterable[str],
    ) -> DataAccessGrant:
        scope = frozenset(record_scope)
        fields = frozenset(allowed_fields)
        if not requester_aid:
            raise DataAccessDenied("requester_aid_required")
        if not purpose:
            raise DataAccessDenied("purpose_required")
        if data_class != self.data_class:
            raise DataAccessDenied("data_class_mismatch")
        if not scope:
            raise DataAccessDenied("record_scope_required")
        if not fields:
            raise DataAccessDenied("allowed_fields_required")
        for record_id in scope:
            if record_id not in self._objects:
                raise DataAccessDenied("unknown_record")
            if purpose not in self._record_purposes.get(record_id, frozenset()):
                raise DataAccessDenied("purpose_mismatch")
        grant = DataAccessGrant(
            grant_id=secrets.token_urlsafe(16),
            requester_aid=requester_aid,
            purpose=purpose,
            data_class=data_class,
            record_scope=scope,
            allowed_fields=fields,
        )
        self._grants[grant.grant_id] = grant
        return grant

    def list_records(self, grant: DataAccessGrant) -> list[DataRecord]:
        checked = self._validated_grant(grant)
        return [
            stored.record
            for record_id, stored in self._objects.items()
            if record_id in checked.record_scope and stored.record.data_class == checked.data_class
        ]

    def read_projection(
        self,
        *,
        grant: DataAccessGrant,
        record_id: str,
        dek: bytes,
        requested_fields: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        checked = self._validated_grant(grant)
        if record_id not in checked.record_scope:
            raise DataAccessDenied("record_out_of_scope")
        stored = self.get(record_id)
        if stored.record.data_class != checked.data_class:
            raise DataAccessDenied("data_class_mismatch")
        fields = frozenset(requested_fields or checked.allowed_fields)
        if not fields:
            raise DataAccessDenied("requested_fields_required")
        if not fields.issubset(checked.allowed_fields):
            raise DataAccessDenied("field_not_allowed")
        payload = json.loads(self.decrypt_with_dek(stored, dek).decode("utf-8"))
        return {field: payload[field] for field in sorted(fields) if field in payload}

    def _validated_grant(self, grant: DataAccessGrant) -> DataAccessGrant:
        registered = self._grants.get(grant.grant_id)
        if registered != grant:
            raise DataAccessDenied("unknown_or_tampered_grant")
        if not grant.requester_aid:
            raise DataAccessDenied("requester_aid_required")
        if not grant.purpose:
            raise DataAccessDenied("purpose_required")
        if grant.data_class != self.data_class:
            raise DataAccessDenied("data_class_mismatch")
        return grant

    def _validate_record_class(self, record: DataRecord) -> None:
        if record.data_class != self.data_class:
            raise ValueError(f"{self.__class__.__name__} cannot store {record.data_class!r} records")

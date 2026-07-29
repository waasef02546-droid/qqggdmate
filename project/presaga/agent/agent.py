"""In-process PRE-SAGA agent runtime bridge.

This module deliberately models the *local* part of a SAGA-like agent
lifecycle.  It has no socket listener, mTLS transport, certificate handling,
or cross-process state synchronisation.  The bridge exists to connect the
existing Provider, policy, token, PRE and encrypted-store components in a
repeatable Alice/Bob/Mallory execution path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from presaga.protocol.schemas import ContactToken, DataAccessRequest, DataRecord, DataToken
from presaga.storage.encrypted_store import EncryptedStore

if TYPE_CHECKING:
    from presaga.provider.app import PREProviderApp, TrustedManagementPlane


class AgentRuntimeError(RuntimeError):
    """Raised when an in-process lifecycle operation cannot continue."""


@dataclass(frozen=True)
class AgentMaterial:
    """Agent identity material used by the prototype runtime only."""

    aid: str
    public_key: bytes
    private_key: bytes


# Keep the original public identity name for existing callers.
Agent = AgentMaterial


@dataclass(frozen=True)
class RuntimeAuditEvent:
    """Local lifecycle evidence; Provider audit remains the authority for PRE."""

    timestamp: datetime
    phase: str
    decision: str
    reason: str
    peer_aid: str | None = None
    token_id: str | None = None
    record_id: str | None = None


@dataclass
class PREAgent:
    """Minimal local agent runtime that drives the PRE-SAGA authorization flow.

    State transitions are ``registered -> contact_session -> data_token ->
    decrypt -> audit``.  ``PREAgent`` is intentionally an in-process bridge:
    callers provide the owner material and encrypted store directly when a
    requester needs a key transformation.  It must not be presented as a
    replacement for SAGA's mTLS/socket based runtime.
    """

    material: AgentMaterial
    provider: "PREProviderApp"
    management: "TrustedManagementPlane | None" = None
    local_stores: dict[str, EncryptedStore] = field(default_factory=dict)
    contact_token_cache: dict[str, ContactToken] = field(default_factory=dict, init=False)
    data_token_cache: dict[str, DataToken] = field(default_factory=dict, init=False)
    _request_cache: dict[str, DataAccessRequest] = field(default_factory=dict, init=False)
    lifecycle: list[RuntimeAuditEvent] = field(default_factory=list, init=False)
    registered: bool = field(default=False, init=False)

    @property
    def aid(self) -> str:
        return self.material.aid

    def register_with_provider(self) -> None:
        if self.management is None:
            raise AgentRuntimeError("trusted management capability is required for registration")
        self.management.register_agent(self.aid, self.material.public_key)
        self.registered = True
        self._audit("registered", "allow", "agent_registered")

    def attach_store(self, name: str, store: EncryptedStore) -> None:
        """Attach an owner-local encrypted store for explicit runtime scenarios."""
        self.local_stores[name] = store

    def set_contact_policy(self, rulebook: list[dict[str, int | str]]) -> None:
        self._require_registered()
        if self.management is None:
            raise AgentRuntimeError("trusted management capability is required for policy changes")
        self.management.set_contact_rulebook(self.aid, rulebook)
        self._audit("contact_policy", "allow", "rulebook_set")

    def open_contact_session(self, owner_aid: str) -> ContactToken | None:
        self._require_registered()
        token = self.provider.issue_contact_session(owner_aid=owner_aid, requester_aid=self.aid)
        if token is None:
            self._audit("contact_session", "deny", "contact_denied", peer_aid=owner_aid)
            return None
        decision = self.provider.validate_contact_session(token, owner_aid=owner_aid, requester_aid=self.aid)
        if decision.effect != "allow":
            self._audit("contact_session", "deny", decision.reason, peer_aid=owner_aid, token_id=token.token_id)
            return None
        self.contact_token_cache[owner_aid] = token
        self._audit("contact_session", "allow", decision.reason, peer_aid=owner_aid, token_id=token.token_id)
        return token

    def request_data_token(self, record: DataRecord, purpose: str) -> DataToken | None:
        self._require_registered()
        if record.owner_aid not in self.contact_token_cache:
            self._audit("data_token", "deny", "contact_session_required", peer_aid=record.owner_aid, record_id=record.record_id)
            return None
        request = DataAccessRequest(
            request_id=f"runtime-{uuid4().hex}",
            owner_aid=record.owner_aid,
            requester_aid=self.aid,
            record_id=record.record_id,
            data_class=record.data_class,
            data_subclass=record.data_subclass,
            purpose=purpose,
            version=record.version,
            requester_public_key=self.material.public_key,
        )
        decision = self.provider.evaluate_data_request(request)
        if decision.effect != "allow":
            self._audit("data_token", "deny", decision.reason, peer_aid=record.owner_aid, record_id=record.record_id)
            return None
        contact_token = self.contact_token_cache[record.owner_aid]
        issuance = self.provider.request_data_token(contact_token=contact_token, request=request)
        if issuance.token is None:
            self._audit(
                "data_token",
                "deny",
                issuance.decision.reason,
                peer_aid=record.owner_aid,
                record_id=record.record_id,
            )
            return None
        token = issuance.token
        self.data_token_cache[token.token_id] = token
        self._request_cache[token.token_id] = request
        self._audit("data_token", "allow", "token_issued", peer_aid=record.owner_aid, token_id=token.token_id, record_id=record.record_id)
        return token

    def request_re_encryption(
        self,
        *,
        token_id: str,
        owner: "PREAgent",
        store: EncryptedStore,
        record_id: str,
    ) -> bytes | None:
        """Request a one-time DEK transformation using cached token context."""
        token = self.data_token_cache.get(token_id)
        request = self._request_cache.get(token_id)
        if token is None or request is None:
            raise AgentRuntimeError("unknown data token")
        if owner.aid != request.owner_aid:
            raise AgentRuntimeError("owner does not match token request")
        stored = store.get(record_id)
        _assert_request_matches_record(request, stored.record)
        owner_wrap = store.resolve_active_owner_wrap(stored)
        wrap_context = store.wrap_context(stored.record, owner_wrap.provenance)
        rekey = store.backend.generate_rekey(
            owner.material.private_key,
            self.material.public_key,
            wrap_context,
        )
        result = self.provider.request_re_encryption(
            contact_token=self.contact_token_cache.get(token.owner_aid),
            token=token,
            request=request,
            stored=stored,
            rekey=rekey,
        )
        if result.decision != "allow" or result.transformed_encrypted_dek is None:
            self._audit("re_encryption", "deny", result.reason, peer_aid=owner.aid, token_id=token_id, record_id=record_id)
            return None
        self._audit("re_encryption", "allow", result.reason, peer_aid=owner.aid, token_id=token_id, record_id=record_id)
        return result.transformed_encrypted_dek

    def decrypt_stored_object(self, *, store: EncryptedStore, record_id: str, transformed_encrypted_dek: bytes) -> bytes:
        """Unwrap the requester-bound DEK and decrypt one authenticated record."""
        stored = store.get(record_id)
        owner_wrap = store.resolve_active_owner_wrap(stored)
        wrap_context = store.wrap_context(stored.record, owner_wrap.provenance)
        dek = store.backend.unwrap_dek(
            transformed_encrypted_dek,
            self.material.private_key,
            wrap_context,
        )
        plaintext = store.decrypt_with_dek(stored, dek)
        self._audit("decrypt", "allow", "record_decrypted", peer_aid=stored.record.owner_aid, record_id=record_id)
        self._audit("audit", "allow", "lifecycle_recorded", peer_aid=stored.record.owner_aid, record_id=record_id)
        return plaintext

    def _require_registered(self) -> None:
        if not self.registered:
            raise AgentRuntimeError("agent must register with provider first")

    def _audit(self, phase: str, decision: str, reason: str, *, peer_aid: str | None = None, token_id: str | None = None, record_id: str | None = None) -> None:
        self.lifecycle.append(
            RuntimeAuditEvent(
                timestamp=datetime.now(timezone.utc),
                phase=phase,
                decision=decision,
                reason=reason,
                peer_aid=peer_aid,
                token_id=token_id,
                record_id=record_id,
            )
        )


def _assert_request_matches_record(request: DataAccessRequest, record: DataRecord) -> None:
    """Reject a stored object whose immutable identity differs from the token request."""
    if (
        request.record_id != record.record_id
        or request.owner_aid != record.owner_aid
        or request.data_class != record.data_class
        or request.data_subclass != record.data_subclass
        or request.version != record.version
    ):
        raise AgentRuntimeError("stored object does not match token request")

"""Provider / PRE proxy orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import ContactToken, DataAccessRequest, DataToken
from presaga.provider.audit import AuditLogger
from presaga.provider.saga_adapter import SagaCompatibleAdapter
from presaga.provider.token_service import TokenService


@dataclass(frozen=True)
class TransformResult:
    transformed_encrypted_dek: bytes | None
    audit_id: str
    decision: str
    reason: str


class PREProxy:
    def __init__(
        self,
        backend: PREBackend,
        token_service: TokenService,
        contact_authorizer: SagaCompatibleAdapter,
        audit: AuditLogger,
    ):
        self.backend = backend
        self.token_service = token_service
        self.contact_authorizer = contact_authorizer
        self.audit = audit

    def transform(
        self,
        *,
        contact_token: ContactToken | None,
        token: DataToken,
        request: DataAccessRequest,
        encrypted_dek_owner: bytes,
        rekey: bytes,
        now: datetime | None = None,
    ) -> TransformResult:
        checked_at = now or datetime.now(timezone.utc)
        if contact_token is None:
            return self._deny(token, request, "contact_session_not_found")
        contact_decision = self.contact_authorizer.validate_contact_token(
            contact_token,
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            now=checked_at,
        )
        if contact_decision.effect != "allow":
            return self._deny(token, request, contact_decision.reason)
        token_decision = self.token_service.validate_and_consume(
            token,
            request,
            contact_token,
            now=checked_at,
        )
        if token_decision.effect != "allow":
            return self._deny(token, request, token_decision.reason)

        transformed = self.backend.transform(encrypted_dek_owner, rekey)
        event = self.audit.record(
            event_type="pre_transform",
            decision="allow",
            reason="policy_match",
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            record_id=request.record_id,
            data_class=request.data_class,
            purpose=request.purpose,
            policy_id=token.policy_id,
            token_id=token.token_id,
            provider_saw_plaintext_dek=False,
            provider_saw_plaintext_data=False,
        )
        return TransformResult(transformed, event.audit_id, "allow", "policy_match")

    def _deny(self, token: DataToken, request: DataAccessRequest, reason: str) -> TransformResult:
        event = self.audit.record(
            event_type="pre_transform",
            decision="deny",
            reason=reason,
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            record_id=request.record_id,
            data_class=request.data_class,
            purpose=request.purpose,
            policy_id=token.policy_id,
            token_id=token.token_id,
        )
        return TransformResult(None, event.audit_id, "deny", reason)

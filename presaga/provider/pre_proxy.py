"""Provider / PRE proxy orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataAccessRequest, DataToken
from presaga.provider.audit import AuditLogger
from presaga.provider.token_service import TokenService


@dataclass(frozen=True)
class TransformResult:
    transformed_encrypted_dek: bytes | None
    audit_id: str
    decision: str
    reason: str


class PREProxy:
    def __init__(self, backend: PREBackend, token_service: TokenService, audit: AuditLogger):
        self.backend = backend
        self.token_service = token_service
        self.audit = audit

    def transform(
        self,
        *,
        token: DataToken,
        request: DataAccessRequest,
        encrypted_dek_owner: bytes,
        rekey: bytes,
    ) -> TransformResult:
        token_decision = self.token_service.validate(token, request)
        if token_decision.effect != "allow":
            event = self.audit.record(
                event_type="pre_transform",
                decision="deny",
                reason=token_decision.reason,
                owner_aid=request.owner_aid,
                requester_aid=request.requester_aid,
                record_id=request.record_id,
                data_class=request.data_class,
                purpose=request.purpose,
                policy_id=token.policy_id,
                token_id=token.token_id,
            )
            return TransformResult(None, event.audit_id, "deny", token_decision.reason)

        transformed = self.backend.transform(encrypted_dek_owner, rekey)
        self.token_service.consume(token)
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

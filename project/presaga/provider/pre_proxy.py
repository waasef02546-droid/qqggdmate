"""Provider / PRE proxy orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import ContactToken, DataAccessRequest, DataToken
from presaga.provider.audit import AuditLogger
from presaga.provider.registry import AgentRegistry, RegistrationError
from presaga.provider.saga_adapter import SagaCompatibleAdapter
from presaga.provider.token_service import TokenService
from presaga.storage.encrypted_store import StoredObject


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
        registry: AgentRegistry,
    ):
        self.backend = backend
        self.token_service = token_service
        self.contact_authorizer = contact_authorizer
        self.audit = audit
        self.registry = registry

    def transform(
        self,
        *,
        contact_token: ContactToken | None,
        token: DataToken,
        request: DataAccessRequest,
        stored: StoredObject,
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
        # Reject token/request scope failures without consuming the token. The
        # authoritative stored-object check still runs before the atomic
        # consume/transform step.
        token_decision = self.token_service.validate(
            token,
            request,
            contact_token,
            now=checked_at,
        )
        if token_decision.effect != "allow":
            return self._deny(token, request, token_decision.reason)
        trusted_store, trusted_stored, owner_wrap, stored_error = self._resolve_trusted_owner_wrap(
            stored,
            request,
        )
        if stored_error is not None:
            return self._deny(token, request, stored_error)
        token_decision = self.token_service.validate_and_consume(
            token,
            request,
            contact_token,
            now=checked_at,
        )
        if token_decision.effect != "allow":
            return self._deny(token, request, token_decision.reason)

        # The store selected this wrapper from the active authoritative owner
        # registration. Never transform a caller-supplied naked wrapped DEK.
        transformed = self.backend.transform(owner_wrap.encrypted_dek, rekey)
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

    def _resolve_trusted_owner_wrap(
        self,
        supplied: StoredObject,
        request: DataAccessRequest,
    ):
        record = getattr(supplied, "record", None)
        if record is None:
            return None, None, None, "stored_object_invalid"
        if (
            record.record_id != request.record_id
            or record.owner_aid != request.owner_aid
            or record.data_class != request.data_class
            or record.data_subclass != request.data_subclass
            or record.version != request.version
        ):
            return None, None, None, "stored_record_mismatch"

        trusted_store = None
        trusted_stored = None
        for store in self.registry.attached_stores():
            try:
                candidate = store.get(record.record_id)
            except KeyError:
                continue
            except Exception as error:
                if str(error) == "stored_object_not_found":
                    continue
                return None, None, None, "owner_store_unavailable"
            if candidate is supplied or candidate == supplied:
                trusted_store = store
                trusted_stored = candidate
                break
        if trusted_store is None or trusted_stored is None:
            return None, None, None, "stored_object_untrusted"

        try:
            registration = self.registry.resolve_active(record.owner_aid)
            owner_wrap = trusted_store.resolve_active_owner_wrap(trusted_stored)
        except RegistrationError as error:
            return None, None, None, error.reason
        except Exception as error:
            reason = str(error)
            stable = reason if reason in {
                "owner_provenance_missing",
                "owner_provenance_invalid",
                "owner_provenance_mismatch",
                "owner_registration_stale",
                "owner_wrap_not_found",
                "legacy_owner_wrap_unverified",
            } else "owner_provenance_invalid"
            return None, None, None, stable

        provenance = getattr(owner_wrap, "provenance", None)
        if provenance is None:
            return None, None, None, "owner_provenance_missing"
        if not (
            getattr(provenance, "owner_aid", None) == registration.aid
            and getattr(provenance, "registration_id", None) == registration.registration_id
            and getattr(provenance, "registration_version", None) == registration.registration_version
            and getattr(provenance, "public_key_fingerprint", None) == registration.public_key_fingerprint
            and getattr(provenance, "key_algorithm", None) == registration.key_algorithm
        ):
            return None, None, None, "owner_provenance_mismatch"
        return trusted_store, trusted_stored, owner_wrap, None

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

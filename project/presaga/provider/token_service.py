"""Policy-bound data token service."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from threading import RLock

from presaga.protocol.schemas import ContactToken, DataAccessRequest, DataToken, PolicyDecision, TokenDecision
from presaga.provider.registry import AgentRegistry, RegistrationError


class TokenService:
    def __init__(self, issuer_secret: bytes, registry: AgentRegistry):
        self.issuer_secret = issuer_secret
        self.registry = registry
        self._lock = RLock()

    def _issue_data_token(
        self,
        decision: PolicyDecision,
        request: DataAccessRequest,
        contact_token: ContactToken,
        *,
        now: datetime | None = None,
    ) -> DataToken:
        """Create a token after PREProviderApp has verified Contact and data policy."""
        if decision.effect != "allow" or not decision.policy_id or not decision.expires_at:
            raise ValueError("cannot issue token for denied decision")
        issued_at = now or datetime.now(timezone.utc)
        if contact_token.owner_aid != request.owner_aid:
            raise ValueError("contact_owner_mismatch")
        if contact_token.requester_aid != request.requester_aid:
            raise ValueError("contact_requester_mismatch")
        if not (contact_token.not_before <= issued_at <= contact_token.expires_at):
            raise ValueError("contact_token_expired")
        requester_registration = self.registry.resolve_active(request.requester_aid)
        owner_registration = self.registry.resolve_active(request.owner_aid)
        if request.requester_public_key is not None and not hmac.compare_digest(
            request.requester_public_key,
            requester_registration.public_key,
        ):
            raise ValueError("requester_key_mismatch")
        token = DataToken(
            token_id=f"dtok-{secrets.token_hex(8)}",
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            policy_id=decision.policy_id,
            contact_token_id=contact_token.token_id,
            contact_session_ref=contact_token.contact_session_ref,
            allowed_record_ids=[request.record_id],
            allowed_data_classes=[request.data_class],
            allowed_data_subclasses=[request.data_subclass],
            purpose=request.purpose,
            not_before=max(issued_at, contact_token.not_before),
            expires_at=min(decision.expires_at, contact_token.expires_at),
            max_uses=decision.max_uses,
            remaining_uses=decision.max_uses,
            min_version=request.version,
            max_version=request.version,
            requester_public_key_hash=requester_registration.public_key_fingerprint,
            requester_registration_version=requester_registration.registration_version,
            owner_public_key_fingerprint=owner_registration.public_key_fingerprint,
            owner_registration_version=owner_registration.registration_version,
            owner_registration_id=owner_registration.registration_id,
            owner_key_algorithm=owner_registration.key_algorithm,
            issuer_signature="",
        )
        token.issuer_signature = self._sign(token)
        return token

    def validate(
        self,
        token: DataToken,
        request: DataAccessRequest,
        contact_token: ContactToken | None,
        now: datetime | None = None,
    ) -> TokenDecision:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            return self._validate_unlocked(token, request, contact_token, now)

    def validate_and_consume(
        self,
        token: DataToken,
        request: DataAccessRequest,
        contact_token: ContactToken | None,
        now: datetime | None = None,
    ) -> TokenDecision:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            decision = self._validate_unlocked(token, request, contact_token, now)
            if decision.effect != "allow":
                return decision
            token.remaining_uses -= 1
            token.issuer_signature = self._sign(token)
            return decision

    def _validate_unlocked(
        self,
        token: DataToken,
        request: DataAccessRequest,
        contact_token: ContactToken | None,
        now: datetime,
    ) -> TokenDecision:
        if not hmac.compare_digest(token.issuer_signature, self._sign(token)):
            return TokenDecision(effect="deny", reason="token_signature_invalid")
        if not (token.not_before <= now <= token.expires_at):
            return TokenDecision(effect="deny", reason="token_expired")
        if token.remaining_uses <= 0:
            return TokenDecision(effect="deny", reason="token_exhausted")
        if token.owner_aid != request.owner_aid:
            return TokenDecision(effect="deny", reason="owner_mismatch")
        if token.requester_aid != request.requester_aid:
            return TokenDecision(effect="deny", reason="requester_mismatch")
        if request.record_id not in token.allowed_record_ids:
            return TokenDecision(effect="deny", reason="record_scope_denied")
        if request.data_class not in token.allowed_data_classes:
            return TokenDecision(effect="deny", reason="data_class_denied")
        if request.data_subclass not in token.allowed_data_subclasses:
            return TokenDecision(effect="deny", reason="data_class_denied")
        if request.purpose != token.purpose:
            return TokenDecision(effect="deny", reason="purpose_mismatch")
        if not (token.min_version <= request.version <= token.max_version):
            return TokenDecision(effect="deny", reason="version_out_of_bounds")
        try:
            owner_registration = self.registry.resolve_active(request.owner_aid)
            requester_registration = self.registry.resolve_active(request.requester_aid)
        except RegistrationError as error:
            return TokenDecision(effect="deny", reason=error.reason)
        if request.requester_public_key is not None and not hmac.compare_digest(
            request.requester_public_key,
            requester_registration.public_key,
        ):
            return TokenDecision(effect="deny", reason="requester_key_mismatch")
        if (
            token.owner_registration_version != owner_registration.registration_version
            or token.owner_registration_id != owner_registration.registration_id
            or token.owner_key_algorithm != owner_registration.key_algorithm
            or not hmac.compare_digest(
                token.owner_public_key_fingerprint,
                owner_registration.public_key_fingerprint,
            )
        ):
            return TokenDecision(effect="deny", reason="owner_registration_stale")
        if (
            token.requester_registration_version != requester_registration.registration_version
            or not hmac.compare_digest(
                token.requester_public_key_hash,
                requester_registration.public_key_fingerprint,
            )
        ):
            return TokenDecision(effect="deny", reason="requester_registration_stale")
        if contact_token is None:
            return TokenDecision(effect="deny", reason="contact_session_not_found")
        if (
            token.contact_token_id != contact_token.token_id
            or token.contact_session_ref != contact_token.contact_session_ref
        ):
            return TokenDecision(effect="deny", reason="contact_session_mismatch")
        return TokenDecision(effect="allow", reason="token_valid")

    def consume(self, token: DataToken) -> None:
        with self._lock:
            if not hmac.compare_digest(token.issuer_signature, self._sign(token)):
                raise ValueError("token signature invalid")
            if token.remaining_uses <= 0:
                raise ValueError("token exhausted")
            token.remaining_uses -= 1
            token.issuer_signature = self._sign(token)

    def _sign(self, token: DataToken) -> str:
        payload = asdict(token)
        payload["issuer_signature"] = ""
        normalized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(self.issuer_secret, normalized, hashlib.sha256).hexdigest()

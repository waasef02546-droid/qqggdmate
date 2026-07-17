"""Policy-bound data token service."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict
from datetime import datetime, timezone

from presaga.protocol.schemas import DataAccessRequest, DataToken, PolicyDecision, TokenDecision


class TokenService:
    def __init__(self, issuer_secret: bytes):
        self.issuer_secret = issuer_secret

    def issue_data_token(self, decision: PolicyDecision, request: DataAccessRequest) -> DataToken:
        if decision.effect != "allow" or not decision.policy_id or not decision.expires_at:
            raise ValueError("cannot issue token for denied decision")
        token = DataToken(
            token_id=f"dtok-{secrets.token_hex(8)}",
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            policy_id=decision.policy_id,
            allowed_record_ids=[request.record_id],
            allowed_data_classes=[request.data_class],
            allowed_data_subclasses=[request.data_subclass],
            purpose=request.purpose,
            not_before=request.timestamp,
            expires_at=decision.expires_at,
            max_uses=decision.max_uses,
            remaining_uses=decision.max_uses,
            min_version=request.version,
            max_version=request.version,
            requester_public_key_hash=self.key_hash(request.requester_public_key),
            issuer_signature="",
        )
        token.issuer_signature = self._sign(token)
        return token

    def validate(self, token: DataToken, request: DataAccessRequest, now: datetime | None = None) -> TokenDecision:
        now = now or datetime.now(timezone.utc)
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
        if token.requester_public_key_hash != self.key_hash(request.requester_public_key):
            return TokenDecision(effect="deny", reason="requester_key_mismatch")
        return TokenDecision(effect="allow", reason="token_valid")

    def consume(self, token: DataToken) -> None:
        if token.remaining_uses <= 0:
            raise ValueError("token exhausted")
        token.remaining_uses -= 1
        token.issuer_signature = self._sign(token)

    def key_hash(self, public_key: bytes) -> str:
        return hashlib.sha256(public_key).hexdigest()

    def _sign(self, token: DataToken) -> str:
        payload = asdict(token)
        payload["issuer_signature"] = ""
        normalized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(self.issuer_secret, normalized, hashlib.sha256).hexdigest()

"""SAGA-compatible contact authorization adapter.

The adapter keeps PRE-SAGA aligned with the SAGA baseline at the contact layer:
an owner agent publishes a contact rulebook, a requester AID is matched against
that rulebook, budget is consumed, and the Provider emits a signed contact
token. Data access is still decided later by PRE-SAGA Data Sharing Policy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from presaga.protocol.schemas import ContactToken, TokenDecision
from presaga.provider.contact_policy import SAGAStyleContactPolicy


@dataclass(frozen=True)
class ParsedAID:
    user_id: str
    agent_name: str


def parse_aid(aid: str) -> ParsedAID:
    """Parse the compact AID form used by the local SAGA-compatible prototype."""

    if ":" not in aid:
        raise ValueError("AID must use '<user-id>:<agent-name>' format")
    user_id, agent_name = aid.split(":", 1)
    if not user_id or not agent_name:
        raise ValueError("AID user-id and agent-name must be non-empty")
    return ParsedAID(user_id=user_id, agent_name=agent_name)


class SagaCompatibleAdapter:
    """Issue and validate signed contact tokens from SAGA-style rulebooks."""

    def __init__(self, issuer_secret: bytes, *, contact_ttl_seconds: int = 300):
        self.issuer_secret = issuer_secret
        self.contact_ttl_seconds = contact_ttl_seconds
        self._rulebooks: dict[str, SAGAStyleContactPolicy] = {}

    def set_rulebook(self, owner_aid: str, rulebook: list[dict[str, int | str]]) -> None:
        parse_aid(owner_aid)
        self._rulebooks[owner_aid] = SAGAStyleContactPolicy(rulebook)

    def issue_contact_token(
        self,
        *,
        owner_aid: str,
        requester_aid: str,
        now: datetime | None = None,
    ) -> ContactToken | None:
        parse_aid(owner_aid)
        parse_aid(requester_aid)
        policy = self._rulebooks.get(owner_aid)
        if policy is None:
            return None
        decision = policy.evaluate(requester_aid, consume=True)
        if decision.effect != "allow" or decision.matched_pattern is None:
            return None
        issued_at = now or datetime.now(timezone.utc)
        token = ContactToken(
            token_id=f"ctok-{secrets.token_hex(8)}",
            owner_aid=owner_aid,
            requester_aid=requester_aid,
            contact_session_ref=f"contact-{secrets.token_hex(8)}",
            matched_pattern=decision.matched_pattern,
            not_before=issued_at,
            expires_at=issued_at + timedelta(seconds=self.contact_ttl_seconds),
            remaining_budget_after_issue=decision.remaining_budget,
            issuer_signature="",
        )
        token.issuer_signature = self._sign(token)
        return token

    def validate_contact_token(
        self,
        token: ContactToken,
        *,
        owner_aid: str,
        requester_aid: str,
        now: datetime | None = None,
    ) -> TokenDecision:
        now = now or datetime.now(timezone.utc)
        if not hmac.compare_digest(token.issuer_signature, self._sign(token)):
            return TokenDecision(effect="deny", reason="contact_token_signature_invalid")
        if not (token.not_before <= now <= token.expires_at):
            return TokenDecision(effect="deny", reason="contact_token_expired")
        if token.owner_aid != owner_aid:
            return TokenDecision(effect="deny", reason="contact_owner_mismatch")
        if token.requester_aid != requester_aid:
            return TokenDecision(effect="deny", reason="contact_requester_mismatch")
        return TokenDecision(effect="allow", reason="contact_token_valid")

    def _sign(self, token: ContactToken) -> str:
        payload = asdict(token)
        payload["issuer_signature"] = ""
        normalized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(self.issuer_secret, normalized, hashlib.sha256).hexdigest()

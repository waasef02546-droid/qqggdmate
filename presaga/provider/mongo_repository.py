"""MongoDB persistence helpers for PRE-SAGA Provider state."""

from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from pymongo.database import Database

from presaga.protocol.schemas import AuditEvent, ContactToken, DataSharingPolicy, DataToken
from presaga.provider.registry import AgentRecord


class MongoProviderRepository:
    """Persist Provider-side E2E state without changing domain logic."""

    COLLECTIONS = (
        "agents",
        "contact_rulebooks",
        "contact_tokens",
        "data_policies",
        "data_tokens",
        "audit_events",
    )

    def __init__(self, db: Database):
        self.db = db
        self.agents = db["agents"]
        self.contact_rulebooks = db["contact_rulebooks"]
        self.contact_tokens = db["contact_tokens"]
        self.data_policies = db["data_policies"]
        self.data_tokens = db["data_tokens"]
        self.audit_events = db["audit_events"]
        self.agents.create_index("aid", unique=True)
        self.contact_tokens.create_index("token_id", unique=True)
        self.data_policies.create_index("policy_id", unique=True)
        self.data_tokens.create_index("token_id", unique=True)
        self.audit_events.create_index("audit_id", unique=True)

    def reset(self) -> None:
        for collection in self.COLLECTIONS:
            self.db[collection].delete_many({})
        self.db["encrypted_objects"].delete_many({})

    def save_agent(self, record: AgentRecord) -> None:
        self.agents.replace_one(
            {"aid": record.aid},
            {"aid": record.aid, "public_key": _b64(record.public_key)},
            upsert=True,
        )

    def save_contact_rulebook(self, owner_aid: str, rulebook: list[dict[str, int | str]]) -> None:
        self.contact_rulebooks.replace_one(
            {"owner_aid": owner_aid},
            {"owner_aid": owner_aid, "rulebook": rulebook},
            upsert=True,
        )

    def save_contact_token(self, token: ContactToken) -> None:
        self.contact_tokens.replace_one({"token_id": token.token_id}, _jsonish(token), upsert=True)

    def save_data_policy(self, policy: DataSharingPolicy) -> None:
        self.data_policies.replace_one({"policy_id": policy.policy_id}, _jsonish(policy), upsert=True)

    def save_data_token(self, token: DataToken) -> None:
        self.data_tokens.replace_one({"token_id": token.token_id}, _jsonish(token), upsert=True)

    def save_audit_events(self, events: list[AuditEvent]) -> None:
        for event in events:
            self.audit_events.replace_one({"audit_id": event.audit_id}, _jsonish(event), upsert=True)

    def collection_counts(self) -> dict[str, int]:
        return {name: self.db[name].count_documents({}) for name in (*self.COLLECTIONS, "encrypted_objects")}


def _jsonish(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonish(asdict(value))
    if isinstance(value, dict):
        return {key: _jsonish(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonish(item) for item in value]
    if isinstance(value, bytes):
        return _b64(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")

"""MongoDB persistence helpers for PRE-SAGA Provider state."""

from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from pymongo.database import Database

from presaga.protocol.schemas import AuditEvent, ContactToken, DataSharingPolicy, DataToken
from presaga.provider.registry import AgentRecord, PreparedReplacement


class MongoProviderRepository:
    """Persist Provider-side E2E state without changing domain logic."""

    COLLECTIONS = (
        "agents",
        "contact_rulebooks",
        "contact_tokens",
        "data_policies",
        "data_tokens",
        "audit_events",
        "rotation_journal",
    )

    def __init__(self, db: Database):
        self.db = db
        self.agents = db["agents"]
        self.contact_rulebooks = db["contact_rulebooks"]
        self.contact_tokens = db["contact_tokens"]
        self.data_policies = db["data_policies"]
        self.data_tokens = db["data_tokens"]
        self.audit_events = db["audit_events"]
        self.rotation_journal = db["rotation_journal"]
        self.agents.create_index("aid", unique=True)
        self.contact_tokens.create_index("token_id", unique=True)
        self.data_policies.create_index("policy_id", unique=True)
        self.data_tokens.create_index("token_id", unique=True)
        self.audit_events.create_index("audit_id", unique=True)
        self.rotation_journal.create_index("rotation_id", unique=True)
        self.rotation_journal.create_index(
            [("candidate.aid", 1), ("status", 1)],
            unique=True,
            partialFilterExpression={"status": "prepared"},
            name="one_prepared_rotation_per_aid",
        )

    def reset(self) -> None:
        for collection in self.COLLECTIONS:
            self.db[collection].delete_many({})
        self.db["encrypted_objects"].delete_many({})

    def save_agent(self, record: AgentRecord) -> None:
        """Persist an initial registration without last-writer-wins upsert semantics."""
        self.agents.insert_one(_registration_document(record))

    def replace_agent(self, record: AgentRecord, *, expected_version: int) -> None:
        """Persist a registry CAS result only if Mongo still has the expected version."""
        result = self.agents.replace_one(
            {"aid": record.aid, "registration_version": expected_version},
            _registration_document(record),
            upsert=False,
        )
        if result.matched_count != 1:
            raise ValueError("registration_version_conflict")

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

    def save_rotation(self, rotation: PreparedReplacement) -> None:
        """Insert a new immutable-identity rotation journal entry."""
        self.rotation_journal.insert_one(_rotation_document(rotation))

    def replace_rotation(
        self,
        rotation: PreparedReplacement,
        *,
        expected_status: str,
        expected_cleanup_completed: bool,
    ) -> None:
        """Persist a rotation transition only from the expected journal state."""
        result = self.rotation_journal.replace_one(
            {
                "rotation_id": rotation.rotation_id,
                "status": expected_status,
                "cleanup_completed": expected_cleanup_completed,
            },
            _rotation_document(rotation),
            upsert=False,
        )
        if result.matched_count != 1:
            raise ValueError("rotation_state_conflict")

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


def _registration_document(record: AgentRecord) -> dict[str, Any]:
    return {
        "aid": record.aid,
        "public_key": _b64(record.public_key),
        "public_key_fingerprint": record.public_key_fingerprint,
        "registration_version": record.registration_version,
        "status": record.status,
        "registered_by": record.registered_by,
        "registration_id": record.registration_id,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "key_algorithm": record.key_algorithm,
    }


def _rotation_document(rotation: PreparedReplacement) -> dict[str, Any]:
    return {
        "rotation_id": rotation.rotation_id,
        "current_registration_id": rotation.current_registration_id,
        "current_version": rotation.current_version,
        "candidate": _registration_document(rotation.candidate),
        "prepared_by": rotation.prepared_by,
        "owner_object_revisions": [
            {
                "store_id": store_id,
                "objects": dict(sorted(revisions.items())),
            }
            for store_id, revisions in rotation.owner_object_revisions
        ],
        "status": rotation.status,
        "created_at": rotation.created_at.isoformat(),
        "updated_at": rotation.updated_at.isoformat(),
        "cleanup_completed": rotation.cleanup_completed,
    }

"""MongoDB persistence helpers for PRE-SAGA Provider state."""

from __future__ import annotations

import base64
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from presaga.protocol.schemas import AuditEvent, ContactToken, DataSharingPolicy, DataToken
from presaga.provider.json_repository import JsonProviderRepository
from presaga.provider.registry import AgentRecord, PreparedReplacement
from presaga.provider.repository import RepositoryConflict, RepositoryUnavailable


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
        "provider_state",
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
        self.provider_state = db["provider_state"]
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

    def load(self) -> dict[str, Any]:
        """Load the authoritative aggregate; encrypted objects remain in their collection."""
        document = self.provider_state.find_one({"_id": "provider-state"})
        if document is None:
            legacy_collections = tuple(
                name for name in self.COLLECTIONS if name != "provider_state"
            )
            if any(
                self.db[name].find_one({}, {"_id": 1}) is not None
                for name in (*legacy_collections, "encrypted_objects")
            ):
                raise RepositoryUnavailable()
            return JsonProviderRepository.empty_state()
        raw_state = document.get("state")
        if not isinstance(raw_state, dict):
            raise ValueError("Mongo provider state must be an object")
        schema_version = int(raw_state.get("schema_version", 1))
        if schema_version > 3:
            raise ValueError("provider state schema is newer than this implementation")
        state_revision = int(document.get("state_revision", -1))
        if state_revision < 0:
            raise ValueError("provider state revision must be non-negative")
        return {
            **JsonProviderRepository.empty_state(),
            **raw_state,
            "schema_version": schema_version,
            "state_revision": state_revision,
            "encrypted_objects": [],
        }

    def save(
        self,
        state: dict[str, Any],
        *,
        expected_revision: int,
    ) -> int:
        """Replace one authoritative aggregate using a server-side revision CAS."""
        if not isinstance(expected_revision, int) or expected_revision < 0:
            raise RepositoryConflict()
        next_revision = expected_revision + 1
        aggregate = {
            key: value
            for key, value in state.items()
            if key not in {"encrypted_objects", "state_revision"}
        }
        replacement = {
            "_id": "provider-state",
            "state_revision": next_revision,
            "state": _jsonish({**aggregate, "state_revision": next_revision}),
        }
        try:
            result = self.provider_state.replace_one(
                {
                    "_id": "provider-state",
                    "state_revision": expected_revision,
                },
                replacement,
                upsert=expected_revision == 0,
            )
        except DuplicateKeyError as error:
            raise RepositoryConflict() from error
        if result.matched_count != 1 and result.upserted_id is None:
            raise RepositoryConflict()
        return next_revision

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
        aggregate = self.provider_state.find_one({"_id": "provider-state"})
        if aggregate is None:
            return {
                name: self.db[name].count_documents({})
                for name in (*self.COLLECTIONS, "encrypted_objects")
            }
        state = aggregate["state"]
        return {
            "agents": len(state.get("agents", [])),
            "contact_rulebooks": len(state.get("contact_rulebooks", {})),
            "contact_tokens": len(state.get("contact_tokens", [])),
            "data_policies": len(state.get("data_policies", [])),
            "data_tokens": len(state.get("data_tokens", [])),
            "audit_events": len(state.get("audit_events", [])),
            "rotation_journal": len(state.get("rotation_journal", [])),
            "provider_state": 1,
            "encrypted_objects": self.db["encrypted_objects"].count_documents({}),
        }


def _jsonish(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonish(asdict(value))
    if isinstance(value, dict):
        return {key: _jsonish(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
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

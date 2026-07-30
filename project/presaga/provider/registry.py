"""Authoritative, versioned AID-to-public-key registration."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Literal, Protocol


RegistrationStatus = Literal["active", "revoked", "legacy_unverified"]
RotationStatus = Literal["prepared", "committed", "aborted"]
_AID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_FINGERPRINT_DOMAIN = b"PRE-SAGA-AID-KEY-V1\x00"


class RegistrationError(ValueError):
    """Stable fail-closed registration failure."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AgentRecord:
    aid: str
    public_key: bytes
    public_key_fingerprint: str
    registration_version: int
    status: RegistrationStatus
    registered_by: str
    registration_id: str
    created_at: datetime
    updated_at: datetime
    key_algorithm: str = "prototype-pre-public-key"


class OwnerObjectStore(Protocol):
    """Minimum store boundary required for safe owner-key replacement."""

    store_id: str

    def has_owner_objects(self, owner_aid: str) -> bool:
        ...

    def get(self, record_id: str):
        ...

    def owner_object_revisions(self, owner_aid: str) -> dict[str, int]:
        ...

    def stage_owner_rewrap(
        self,
        record_id: str,
        target_registration: AgentRecord,
        source_private_key: bytes,
        rotation_id: str,
        expected_object_revision: int,
    ) -> Any:
        ...

    def cleanup_owner_rotation(
        self,
        record_id: str,
        *,
        rotation_id: str,
        status: Literal["committed", "aborted"],
        source_registration_id: str,
        source_registration_version: int,
        target_registration: AgentRecord,
        original_object_revision: int,
    ) -> Any:
        ...


@dataclass(frozen=True)
class PreparedReplacement:
    """Serializable rotation-journal entry, including terminal history."""

    current_registration_id: str
    current_version: int
    candidate: AgentRecord
    prepared_by: str
    rotation_id: str
    owner_object_revisions: tuple[tuple[str, dict[str, int]], ...]
    status: RotationStatus
    created_at: datetime
    updated_at: datetime
    cleanup_completed: bool = False


class AgentRegistry:
    """Single-process registry with atomic create/replace/revoke operations."""

    def __init__(self, *, key_algorithm: str = "prototype-pre-public-key"):
        if (
            not isinstance(key_algorithm, str)
            or not key_algorithm
            or len(key_algorithm) > 128
        ):
            raise RegistrationError("key_algorithm_invalid")
        self._key_algorithm = key_algorithm
        self._agents: dict[str, AgentRecord] = {}
        self._prepared: dict[str, PreparedReplacement] = {}
        self._rotations: dict[str, PreparedReplacement] = {}
        self._owner_stores: dict[str, OwnerObjectStore] = {}
        self._lock = RLock()

    def attach_store(self, store: OwnerObjectStore) -> None:
        """Attach one trusted store whose owner objects constrain replacement."""
        required_methods = (
            "has_owner_objects",
            "get",
            "owner_object_revisions",
            "stage_owner_rewrap",
            "resolve_active_owner_wrap",
            "cleanup_owner_rotation",
        )
        if not all(callable(getattr(store, method, None)) for method in required_methods):
            raise RegistrationError("owner_store_invalid")
        store_id = getattr(store, "store_id", None)
        if not isinstance(store_id, str) or not store_id or len(store_id) > 128:
            raise RegistrationError("owner_store_id_invalid")
        if getattr(store, "registry", self) is not self:
            raise RegistrationError("owner_store_registry_mismatch")
        with self._lock:
            attached = self._owner_stores.get(store_id)
            if attached is not None and attached is not store:
                raise RegistrationError("owner_store_id_conflict")
            self._owner_stores[store_id] = store

    def attached_stores(self) -> tuple[OwnerObjectStore, ...]:
        with self._lock:
            return tuple(self._owner_stores[key] for key in sorted(self._owner_stores))

    def create(self, aid: str, public_key: bytes, *, actor: str, now: datetime | None = None) -> AgentRecord:
        canonical_aid = validate_aid(aid)
        key = validate_public_key(public_key)
        principal = validate_actor(actor)
        timestamp = now or datetime.now(timezone.utc)
        with self._lock:
            if canonical_aid in self._agents:
                raise RegistrationError("registration_exists")
            record = AgentRecord(
                aid=canonical_aid,
                public_key=key,
                public_key_fingerprint=key_fingerprint(
                    key,
                    key_algorithm=self._key_algorithm,
                ),
                registration_version=1,
                status="active",
                registered_by=principal,
                registration_id=f"areg-{secrets.token_hex(12)}",
                created_at=timestamp,
                updated_at=timestamp,
                key_algorithm=self._key_algorithm,
            )
            self._agents[canonical_aid] = record
            return record

    def replace(
        self,
        aid: str,
        public_key: bytes,
        *,
        actor: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> AgentRecord:
        canonical_aid = validate_aid(aid)
        with self._lock:
            if self._has_owner_objects_unlocked(canonical_aid):
                raise RegistrationError("owner_rotation_required")
        prepared = self.prepare_replace(
            canonical_aid,
            public_key,
            actor=actor,
            expected_version=expected_version,
            now=now,
        )
        return self.commit_prepared_replace(
            canonical_aid,
            actor=actor,
            expected_version=expected_version,
            rotation_id=self.prepared_replacement(canonical_aid).rotation_id,
            now=now,
        )

    def prepare_replace(
        self,
        aid: str,
        public_key: bytes,
        *,
        actor: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> AgentRecord:
        """Prepare version N+1 while leaving the active N registration intact."""
        canonical_aid = validate_aid(aid)
        key = validate_public_key(public_key)
        principal = validate_actor(actor)
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            if canonical_aid in self._prepared:
                raise RegistrationError("registration_replacement_pending")
            if current.status != "active":
                raise RegistrationError("registration_not_active")
            if not isinstance(expected_version, int) or expected_version != current.registration_version:
                raise RegistrationError("registration_version_conflict")
            if hmac.compare_digest(current.public_key_fingerprint, key_fingerprint(key)):
                raise RegistrationError("registration_key_unchanged")
            candidate = replace(
                current,
                public_key=key,
                public_key_fingerprint=key_fingerprint(
                    key,
                    key_algorithm=current.key_algorithm,
                ),
                registration_version=current.registration_version + 1,
                updated_at=now or datetime.now(timezone.utc),
            )
            timestamp = now or datetime.now(timezone.utc)
            prepared = PreparedReplacement(
                current_registration_id=current.registration_id,
                current_version=current.registration_version,
                candidate=candidate,
                prepared_by=principal,
                rotation_id=f"rotation-{secrets.token_hex(12)}",
                owner_object_revisions=tuple(
                    (
                        store_id,
                        dict(self._owner_stores[store_id].owner_object_revisions(canonical_aid)),
                    )
                    for store_id in sorted(self._owner_stores)
                ),
                status="prepared",
                created_at=timestamp,
                updated_at=timestamp,
            )
            self._prepared[canonical_aid] = prepared
            self._rotations[prepared.rotation_id] = prepared
            return candidate

    def prepared_replacement(self, aid: str) -> PreparedReplacement:
        canonical_aid = validate_aid(aid)
        with self._lock:
            try:
                return self._prepared[canonical_aid]
            except KeyError as error:
                raise RegistrationError("registration_replacement_not_prepared") from error

    def commit_prepared_replace(
        self,
        aid: str,
        *,
        actor: str,
        expected_version: int,
        rotation_id: str,
        now: datetime | None = None,
    ) -> AgentRecord:
        """Activate exactly one prepared candidate using a version-and-id CAS."""
        canonical_aid = validate_aid(aid)
        principal = validate_actor(actor)
        if not isinstance(rotation_id, str) or not rotation_id:
            raise RegistrationError("rotation_id_invalid")
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            prepared = self.prepared_replacement(canonical_aid)
            if prepared.prepared_by != principal:
                raise RegistrationError("registration_actor_forbidden")
            if (
                not isinstance(expected_version, int)
                or expected_version != current.registration_version
                or expected_version != prepared.current_version
                or current.registration_id != prepared.current_registration_id
            ):
                raise RegistrationError("registration_version_conflict")
            if not hmac.compare_digest(prepared.rotation_id, rotation_id):
                raise RegistrationError("prepared_rotation_mismatch")
            self._require_rewrap_complete(prepared)
            activated = replace(
                prepared.candidate,
                updated_at=now or datetime.now(timezone.utc),
            )
            self._agents[canonical_aid] = activated
            terminal = replace(
                prepared,
                status="committed",
                updated_at=activated.updated_at,
            )
            self._rotations[prepared.rotation_id] = terminal
            del self._prepared[canonical_aid]
            return activated

    def stage_prepared_rewrap(
        self,
        aid: str,
        *,
        actor: str,
        expected_version: int,
        rotation_id: str,
        store: OwnerObjectStore,
        record_id: str,
        source_private_key: bytes,
        expected_object_revision: int,
    ) -> Any:
        """Stage one candidate wrapper under exact registration/object CAS values."""
        canonical_aid = validate_aid(aid)
        principal = validate_actor(actor)
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            prepared = self.prepared_replacement(canonical_aid)
            if (
                expected_version != current.registration_version
                or expected_version != prepared.current_version
            ):
                raise RegistrationError("registration_version_conflict")
            if not hmac.compare_digest(prepared.rotation_id, rotation_id):
                raise RegistrationError("prepared_rotation_mismatch")
            store_id = getattr(store, "store_id", None)
            snapshots = dict(prepared.owner_object_revisions)
            if (
                not isinstance(store_id, str)
                or self._owner_stores.get(store_id) is not store
                or store_id not in snapshots
            ):
                raise RegistrationError("owner_store_not_attached")
            original_revision = snapshots[store_id].get(record_id)
            if original_revision is None:
                raise RegistrationError("owner_object_not_in_rotation")
            if expected_object_revision != original_revision:
                raise RegistrationError("owner_object_revision_conflict")
            try:
                return store.stage_owner_rewrap(
                    record_id,
                    target_registration=prepared.candidate,
                    source_private_key=source_private_key,
                    rotation_id=prepared.rotation_id,
                    expected_object_revision=expected_object_revision,
                )
            except RegistrationError:
                raise
            except Exception as error:
                reason = getattr(error, "reason", str(error))
                stable = reason if reason in {
                    "stored_object_revision_conflict",
                    "owner_provenance_mismatch",
                    "stored_object_not_found",
                    "stored_object_legacy_unverified",
                    "stored_object_invalid",
                    "owner_registration_not_active",
                    "owner_registration_fingerprint_invalid",
                    "rotation_target_conflict",
                    "owner_wrap_not_found",
                    "owner_wrap_ambiguous",
                    "source_private_key_mismatch",
                    "rotation_owner_mismatch",
                    "rotation_registration_id_mismatch",
                    "rotation_version_invalid",
                    "rotation_key_unchanged",
                    "rotation_actor_mismatch",
                } else "owner_rewrap_failed"
                raise RegistrationError(stable) from error

    def abort_prepared_replace(
        self,
        aid: str,
        *,
        actor: str,
        expected_version: int,
        rotation_id: str,
    ) -> None:
        canonical_aid = validate_aid(aid)
        principal = validate_actor(actor)
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            prepared = self.prepared_replacement(canonical_aid)
            if expected_version != current.registration_version:
                raise RegistrationError("registration_version_conflict")
            if not hmac.compare_digest(prepared.rotation_id, rotation_id):
                raise RegistrationError("prepared_rotation_mismatch")
            timestamp = datetime.now(timezone.utc)
            self._rotations[prepared.rotation_id] = replace(
                prepared,
                status="aborted",
                updated_at=timestamp,
            )
            del self._prepared[canonical_aid]

    def cleanup_rotation(
        self,
        aid: str,
        *,
        actor: str,
        rotation_id: str,
    ) -> PreparedReplacement:
        """Idempotently clean wraps for one committed or aborted journal entry."""
        canonical_aid = validate_aid(aid)
        principal = validate_actor(actor)
        if not isinstance(rotation_id, str) or not rotation_id:
            raise RegistrationError("rotation_id_invalid")
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            try:
                rotation = self._rotations[rotation_id]
            except KeyError as error:
                raise RegistrationError("rotation_not_found") from error
            if rotation.candidate.aid != canonical_aid:
                raise RegistrationError("prepared_rotation_mismatch")
            if rotation.prepared_by != principal:
                raise RegistrationError("registration_actor_forbidden")
            if rotation.status == "prepared":
                raise RegistrationError("rotation_not_terminal")
            if rotation.cleanup_completed:
                return rotation
            for store_id, revisions in rotation.owner_object_revisions:
                store = self._owner_stores.get(store_id)
                if store is None:
                    raise RegistrationError("owner_store_not_attached")
                for record_id, original_revision in sorted(revisions.items()):
                    try:
                        store.cleanup_owner_rotation(
                            record_id,
                            rotation_id=rotation.rotation_id,
                            status=rotation.status,
                            source_registration_id=rotation.current_registration_id,
                            source_registration_version=rotation.current_version,
                            target_registration=rotation.candidate,
                            original_object_revision=original_revision,
                        )
                    except RegistrationError:
                        raise
                    except Exception as error:
                        reason = getattr(error, "reason", str(error))
                        stable = reason if reason in {
                            "owner_object_revision_conflict",
                            "owner_rotation_conflict",
                            "owner_wrap_not_found",
                            "owner_provenance_invalid",
                            "stored_object_not_found",
                        } else "owner_rotation_cleanup_failed"
                        raise RegistrationError(stable) from error
            cleaned = replace(
                rotation,
                cleanup_completed=True,
                updated_at=datetime.now(timezone.utc),
            )
            self._rotations[rotation_id] = cleaned
            return cleaned

    def revoke(
        self,
        aid: str,
        *,
        actor: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> AgentRecord:
        canonical_aid = validate_aid(aid)
        principal = validate_actor(actor)
        with self._lock:
            current = self._get_existing(canonical_aid)
            self._authorize(current, principal)
            if canonical_aid in self._prepared:
                raise RegistrationError("registration_replacement_pending")
            if current.status != "active":
                raise RegistrationError("registration_not_active")
            if not isinstance(expected_version, int) or expected_version != current.registration_version:
                raise RegistrationError("registration_version_conflict")
            revoked = replace(
                current,
                status="revoked",
                registration_version=current.registration_version + 1,
                updated_at=now or datetime.now(timezone.utc),
            )
            self._agents[canonical_aid] = revoked
            return revoked

    def resolve_active(self, aid: str) -> AgentRecord:
        canonical_aid = validate_aid(aid)
        with self._lock:
            record = self._get_existing(canonical_aid)
            if record.status != "active":
                raise RegistrationError("registration_not_active")
            return record

    def get(self, aid: str) -> AgentRecord:
        canonical_aid = validate_aid(aid)
        with self._lock:
            return self._get_existing(canonical_aid)

    def restore(self, record: AgentRecord) -> None:
        """Restore a validated v2 record without bypassing registry invariants."""
        canonical_aid = validate_aid(record.aid)
        validate_public_key(record.public_key)
        validate_actor(record.registered_by)
        if record.registration_version < 1:
            raise RegistrationError("registration_version_invalid")
        if record.status not in ("active", "revoked", "legacy_unverified"):
            raise RegistrationError("registration_status_invalid")
        expected_fingerprint = key_fingerprint(record.public_key, key_algorithm=record.key_algorithm)
        if not hmac.compare_digest(record.public_key_fingerprint, expected_fingerprint):
            raise RegistrationError("registration_fingerprint_invalid")
        with self._lock:
            if canonical_aid in self._agents:
                raise RegistrationError("registration_duplicate_restore")
            self._agents[canonical_aid] = record

    def import_legacy(self, aid: str, public_key: bytes, *, now: datetime | None = None) -> AgentRecord:
        """Quarantine a legacy unauthenticated record; it cannot authorize data operations."""
        canonical_aid = validate_aid(aid)
        key = validate_public_key(public_key)
        timestamp = now or datetime.now(timezone.utc)
        record = AgentRecord(
            aid=canonical_aid,
            public_key=key,
            public_key_fingerprint=key_fingerprint(
                key,
                key_algorithm="legacy-unverified",
            ),
            registration_version=1,
            status="legacy_unverified",
            registered_by="legacy-import",
            registration_id=f"legacy-{secrets.token_hex(12)}",
            created_at=timestamp,
            updated_at=timestamp,
            key_algorithm="legacy-unverified",
        )
        self.restore(record)
        return record

    def snapshot(self) -> tuple[AgentRecord, ...]:
        with self._lock:
            return tuple(self._agents[aid] for aid in sorted(self._agents))

    def rotation_journal(self) -> tuple[PreparedReplacement, ...]:
        with self._lock:
            return tuple(self._rotations[key] for key in sorted(self._rotations))

    def restore_rotation(self, rotation: PreparedReplacement) -> None:
        """Restore one validated journal entry after registrations and stores."""
        if rotation.status not in ("prepared", "committed", "aborted"):
            raise RegistrationError("rotation_status_invalid")
        if not isinstance(rotation.rotation_id, str) or not rotation.rotation_id:
            raise RegistrationError("rotation_id_invalid")
        validate_actor(rotation.prepared_by)
        candidate = rotation.candidate
        validate_aid(candidate.aid)
        validate_public_key(candidate.public_key)
        expected_fingerprint = key_fingerprint(
            candidate.public_key,
            key_algorithm=candidate.key_algorithm,
        )
        if not hmac.compare_digest(candidate.public_key_fingerprint, expected_fingerprint):
            raise RegistrationError("registration_fingerprint_invalid")
        if candidate.registration_id != rotation.current_registration_id:
            raise RegistrationError("rotation_registration_id_mismatch")
        if candidate.registration_version != rotation.current_version + 1:
            raise RegistrationError("rotation_version_invalid")
        if rotation.cleanup_completed and rotation.status == "prepared":
            raise RegistrationError("rotation_cleanup_state_invalid")
        seen_store_ids: set[str] = set()
        for store_id, revisions in rotation.owner_object_revisions:
            if (
                not isinstance(store_id, str)
                or not store_id
                or store_id in seen_store_ids
                or store_id not in self._owner_stores
            ):
                raise RegistrationError("owner_store_not_attached")
            seen_store_ids.add(store_id)
            if not isinstance(revisions, dict) or any(
                not isinstance(record_id, str)
                or not record_id
                or not isinstance(revision, int)
                or revision < 1
                for record_id, revision in revisions.items()
            ):
                raise RegistrationError("rotation_inventory_invalid")
        with self._lock:
            if rotation.rotation_id in self._rotations:
                raise RegistrationError("rotation_duplicate_restore")
            current = self._get_existing(candidate.aid)
            if rotation.status in ("prepared", "aborted"):
                if (
                    current.registration_id != rotation.current_registration_id
                    or current.registration_version != rotation.current_version
                ):
                    raise RegistrationError("rotation_registry_state_mismatch")
            elif (
                current.registration_id != candidate.registration_id
                or current.registration_version != candidate.registration_version
                or current.public_key_fingerprint != candidate.public_key_fingerprint
            ):
                raise RegistrationError("rotation_registry_state_mismatch")
            self._validate_recovered_inventory(rotation)
            if rotation.status == "prepared":
                if candidate.aid in self._prepared:
                    raise RegistrationError("registration_replacement_pending")
                self._prepared[candidate.aid] = rotation
            self._rotations[rotation.rotation_id] = rotation

    def _validate_recovered_inventory(
        self,
        rotation: PreparedReplacement,
    ) -> None:
        """Reject journal/object combinations outside reachable lifecycle states."""
        candidate = rotation.candidate
        for store_id, original_revisions in rotation.owner_object_revisions:
            store = self._owner_stores[store_id]
            try:
                current_revisions = dict(store.owner_object_revisions(candidate.aid))
            except Exception as error:
                raise RegistrationError("owner_store_unavailable") from error
            if set(current_revisions) != set(original_revisions):
                raise RegistrationError("owner_rotation_object_set_changed")
            for record_id, original_revision in original_revisions.items():
                current_revision = current_revisions[record_id]
                allowed_revisions = (
                    {original_revision, original_revision + 1}
                    if rotation.status == "prepared"
                    else {original_revision, original_revision + 1, original_revision + 2}
                )
                if current_revision not in allowed_revisions:
                    raise RegistrationError("rotation_recovery_state_invalid")
                try:
                    stored = store.get(record_id)
                except Exception as error:
                    raise RegistrationError("rotation_recovery_state_invalid") from error
                wraps = getattr(stored, "owner_wraps", ())
                source_count = sum(
                    getattr(wrap, "provenance", None) is not None
                    and getattr(wrap.provenance, "registration_id", None)
                    == rotation.current_registration_id
                    and getattr(wrap.provenance, "registration_version", None)
                    == rotation.current_version
                    for wrap in wraps
                )
                target_count = sum(
                    _provenance_matches_registration(
                        getattr(wrap, "provenance", None),
                        candidate,
                    )
                    and getattr(wrap, "rotation_id", None) == rotation.rotation_id
                    for wrap in wraps
                )
                if current_revision == original_revision and (
                    source_count != 1 or target_count != 0
                ):
                    raise RegistrationError("rotation_recovery_state_invalid")
                if current_revision == original_revision + 1 and (
                    source_count != 1 or target_count != 1
                ):
                    raise RegistrationError("rotation_recovery_state_invalid")
                if current_revision == original_revision + 2:
                    expected = (
                        source_count == 0 and target_count == 1
                        if rotation.status == "committed"
                        else source_count == 1 and target_count == 0
                    )
                    if not expected:
                        raise RegistrationError("rotation_recovery_state_invalid")
                if rotation.status == "committed" and current_revision == original_revision:
                    raise RegistrationError("rotation_recovery_state_invalid")

    def _has_owner_objects_unlocked(self, aid: str) -> bool:
        for store in self._owner_stores.values():
            try:
                if store.has_owner_objects(aid):
                    return True
            except Exception as error:
                raise RegistrationError("owner_store_unavailable") from error
        return False

    def _require_rewrap_complete(self, prepared: PreparedReplacement) -> None:
        candidate = prepared.candidate
        for store_id, original_revisions in prepared.owner_object_revisions:
            store = self._owner_stores.get(store_id)
            if store is None:
                raise RegistrationError("owner_store_not_attached")
            try:
                current_revisions = dict(store.owner_object_revisions(candidate.aid))
            except Exception as error:
                raise RegistrationError("owner_store_unavailable") from error
            if set(current_revisions) != set(original_revisions):
                raise RegistrationError("owner_rotation_object_set_changed")
            for record_id, original_revision in original_revisions.items():
                if current_revisions[record_id] != original_revision + 1:
                    raise RegistrationError("owner_rewrap_incomplete")
                try:
                    stored = store.get(record_id)
                except Exception as error:
                    raise RegistrationError("owner_rewrap_incomplete") from error
                wraps = getattr(stored, "owner_wraps", ())
                if not any(
                    _provenance_matches_registration(
                        getattr(wrap, "provenance", None),
                        candidate,
                    )
                    and getattr(wrap, "rotation_id", None) == prepared.rotation_id
                    for wrap in wraps
                ):
                    raise RegistrationError("owner_rewrap_incomplete")

    def _get_existing(self, aid: str) -> AgentRecord:
        try:
            return self._agents[aid]
        except KeyError as error:
            raise RegistrationError("registration_not_found") from error

    @staticmethod
    def _authorize(record: AgentRecord, actor: str) -> None:
        if not hmac.compare_digest(record.registered_by, actor):
            raise RegistrationError("registration_actor_forbidden")


def _provenance_matches_registration(provenance: object, registration: AgentRecord) -> bool:
    if provenance is None:
        return False
    return (
        getattr(provenance, "owner_aid", None) == registration.aid
        and getattr(provenance, "registration_id", None) == registration.registration_id
        and getattr(provenance, "registration_version", None) == registration.registration_version
        and getattr(provenance, "public_key_fingerprint", None) == registration.public_key_fingerprint
        and getattr(provenance, "key_algorithm", None) == registration.key_algorithm
    )


def validate_aid(aid: str) -> str:
    if not isinstance(aid, str) or not _AID_RE.fullmatch(aid):
        raise RegistrationError("aid_invalid")
    return aid


def validate_actor(actor: str) -> str:
    if not isinstance(actor, str) or not actor or len(actor) > 128:
        raise RegistrationError("management_principal_invalid")
    return actor


def validate_public_key(public_key: bytes) -> bytes:
    if not isinstance(public_key, bytes) or len(public_key) < 16 or len(public_key) > 16384:
        raise RegistrationError("public_key_invalid")
    return public_key


def key_fingerprint(public_key: bytes, *, key_algorithm: str = "prototype-pre-public-key") -> str:
    key = validate_public_key(public_key)
    if not isinstance(key_algorithm, str) or not key_algorithm:
        raise RegistrationError("key_algorithm_invalid")
    payload = _FINGERPRINT_DOMAIN + key_algorithm.encode("ascii") + b"\x00" + key
    return hashlib.sha256(payload).hexdigest()

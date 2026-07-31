"""Registration-bound encrypted storage for the PRE-SAGA prototype."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, replace
from threading import RLock
from typing import Literal

from presaga.crypto import envelope
from presaga.crypto.key_custody import (
    OwnerRewrapArtifact,
    OwnerRewrapRequest,
    verify_custody_artifact,
)
from presaga.crypto.key_rotation import data_context, owner_wrap_context
from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.registry import AgentRecord, AgentRegistry, key_fingerprint


STORAGE_SCHEMA_VERSION = 2


class StorageProvenanceError(ValueError):
    """Stable fail-closed storage/provenance failure."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class OwnerKeyProvenance:
    owner_aid: str
    registration_id: str
    registration_version: int
    public_key_fingerprint: str
    key_algorithm: str

    @classmethod
    def from_registration(cls, registration: AgentRecord) -> "OwnerKeyProvenance":
        if registration.status != "active":
            raise StorageProvenanceError("owner_registration_not_active")
        expected = key_fingerprint(
            registration.public_key,
            key_algorithm=registration.key_algorithm,
        )
        if not hmac.compare_digest(registration.public_key_fingerprint, expected):
            raise StorageProvenanceError("owner_registration_fingerprint_invalid")
        return cls(
            owner_aid=registration.aid,
            registration_id=registration.registration_id,
            registration_version=registration.registration_version,
            public_key_fingerprint=registration.public_key_fingerprint,
            key_algorithm=registration.key_algorithm,
        )


@dataclass(frozen=True)
class OwnerWrappedDEK:
    encrypted_dek: bytes
    provenance: OwnerKeyProvenance
    rotation_id: str | None = None
    custody_request_digest: bytes | None = None


@dataclass(frozen=True)
class StoredObject:
    record: DataRecord
    ciphertext: envelope.EnvelopeCiphertext
    owner_wraps: tuple[OwnerWrappedDEK, ...]
    object_revision: int = 1
    schema_version: int = STORAGE_SCHEMA_VERSION


class EncryptedStore:
    """Single-process store with exact owner-registration provenance."""

    def __init__(
        self,
        backend: PREBackend,
        registry: AgentRegistry,
        *,
        store_id: str = "primary-encrypted-store",
    ):
        if not isinstance(store_id, str) or not store_id or len(store_id) > 128:
            raise StorageProvenanceError("owner_store_id_invalid")
        self.backend = backend
        self.registry = registry
        self.store_id = store_id
        self._objects: dict[str, StoredObject] = {}
        self._lock = RLock()
        attach_store = getattr(registry, "attach_store", None)
        if callable(attach_store):
            attach_store(self)

    def put(self, record: DataRecord, plaintext: bytes) -> StoredObject:
        registration = self.registry.resolve_active(record.owner_aid)
        provenance = OwnerKeyProvenance.from_registration(registration)
        dek = envelope.generate_dek()
        ciphertext = envelope.encrypt(plaintext, dek, self._aad(record))
        encrypted_dek = self.backend.wrap_dek(
            dek,
            registration.public_key,
            self.wrap_context(record, provenance),
        )
        stored = StoredObject(
            record=record,
            ciphertext=ciphertext,
            owner_wraps=(OwnerWrappedDEK(encrypted_dek, provenance),),
        )
        with self._lock:
            if record.record_id in self._objects:
                raise StorageProvenanceError("stored_object_exists")
            self._objects[record.record_id] = stored
        return stored

    def get(self, record_id: str) -> StoredObject:
        with self._lock:
            try:
                return self._objects[record_id]
            except KeyError as error:
                raise KeyError(record_id) from error

    def has_owner_objects(self, owner_aid: str) -> bool:
        with self._lock:
            return any(stored.record.owner_aid == owner_aid for stored in self._objects.values())

    def owner_object_revisions(self, owner_aid: str) -> dict[str, int]:
        with self._lock:
            return {
                record_id: stored.object_revision
                for record_id, stored in sorted(self._objects.items())
                if stored.record.owner_aid == owner_aid
            }

    def snapshot(self) -> tuple[StoredObject, ...]:
        """Return a deterministic immutable snapshot for provider persistence."""
        with self._lock:
            return tuple(self._objects[key] for key in sorted(self._objects))

    def restore(self, stored: StoredObject) -> None:
        """Restore one validated object without overwriting an existing record."""
        self._validate_stored_object(stored)
        if stored.ciphertext.aad != self._aad(stored.record):
            raise StorageProvenanceError("stored_object_aad_mismatch")
        with self._lock:
            if stored.record.record_id in self._objects:
                raise StorageProvenanceError("stored_object_exists")
            self._objects[stored.record.record_id] = stored

    def resolve_active_owner_wrap(
        self,
        stored_or_record_id: StoredObject | str,
    ) -> OwnerWrappedDEK:
        stored = (
            self.get(stored_or_record_id)
            if isinstance(stored_or_record_id, str)
            else stored_or_record_id
        )
        self._validate_stored_object(stored)
        registration = self.registry.resolve_active(stored.record.owner_aid)
        active = OwnerKeyProvenance.from_registration(registration)
        matches = [wrapped for wrapped in stored.owner_wraps if wrapped.provenance == active]
        if len(matches) != 1:
            reason = "owner_wrap_not_found" if not matches else "owner_provenance_invalid"
            raise StorageProvenanceError(reason)
        return matches[0]

    def stage_owner_rewrap(
        self,
        record_id: str,
        target_registration: AgentRecord,
        artifact: OwnerRewrapArtifact,
        rotation_id: str,
        expected_object_revision: int,
    ) -> StoredObject:
        if not isinstance(rotation_id, str) or not rotation_id:
            raise StorageProvenanceError("rotation_id_invalid")
        with self._lock:
            stored = self.get(record_id)
            staged = self._stage_owner_rewrap_object(
                stored,
                target_registration=target_registration,
                artifact=artifact,
                rotation_id=rotation_id,
                expected_object_revision=expected_object_revision,
            )
            self._objects[record_id] = staged
            return staged

    def build_owner_rewrap_request(
        self,
        record_id: str,
        target_registration: AgentRecord,
        rotation_id: str,
        expected_object_revision: int,
    ) -> OwnerRewrapRequest:
        """Export a deterministic request containing public rotation material only."""
        if not isinstance(rotation_id, str) or not rotation_id:
            raise StorageProvenanceError("rotation_id_invalid")
        with self._lock:
            stored = self.get(record_id)
            request = self._build_owner_rewrap_request(
                stored,
                target_registration=target_registration,
                rotation_id=rotation_id,
                expected_object_revision=expected_object_revision,
            )
            if stored.object_revision not in {
                expected_object_revision,
                expected_object_revision + 1,
            }:
                raise StorageProvenanceError("owner_object_revision_conflict")
            return request

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
    ) -> StoredObject:
        """Conditionally clean one rotation's wraps; safe to retry after interruption."""
        with self._lock:
            stored = self.get(record_id)
            cleaned = self._cleanup_owner_rotation_object(
                stored,
                rotation_id=rotation_id,
                status=status,
                source_registration_id=source_registration_id,
                source_registration_version=source_registration_version,
                target_registration=target_registration,
                original_object_revision=original_object_revision,
            )
            self._objects[record_id] = cleaned
            return cleaned

    def decrypt_with_dek(self, stored: StoredObject, dek: bytes) -> bytes:
        self._validate_stored_object(stored)
        return envelope.decrypt(stored.ciphertext, dek, aad=self._aad(stored.record))

    def context(self, record: DataRecord) -> bytes:
        """Return the current registration-bound owner-wrap context."""
        registration = self.registry.resolve_active(record.owner_aid)
        return self.wrap_context(record, OwnerKeyProvenance.from_registration(registration))

    def wrap_context(self, record: DataRecord, provenance: OwnerKeyProvenance) -> bytes:
        if record.owner_aid != provenance.owner_aid:
            raise StorageProvenanceError("owner_provenance_aid_mismatch")
        binding = data_context(record.owner_aid, record.record_id, record.data_class, record.version)
        return owner_wrap_context(binding, provenance)

    def _stage_owner_rewrap_object(
        self,
        stored: StoredObject,
        *,
        target_registration: AgentRecord,
        artifact: OwnerRewrapArtifact,
        rotation_id: str,
        expected_object_revision: int,
    ) -> StoredObject:
        request = self._build_owner_rewrap_request(
            stored,
            target_registration=target_registration,
            rotation_id=rotation_id,
            expected_object_revision=expected_object_revision,
        )
        try:
            verify_custody_artifact(request, artifact, backend=self.backend)
        except Exception as error:
            reason = getattr(error, "reason", str(error))
            stable = reason if isinstance(reason, str) and reason.startswith("custody_") else (
                "custody_artifact_invalid"
            )
            raise StorageProvenanceError(stable) from error

        target = OwnerKeyProvenance.from_registration(target_registration)

        existing_rotation = [
            wrapped for wrapped in stored.owner_wraps if wrapped.rotation_id == rotation_id
        ]
        if existing_rotation:
            if (
                len(existing_rotation) == 1
                and existing_rotation[0].provenance == target
                and existing_rotation[0].encrypted_dek == artifact.target_encrypted_dek
                and existing_rotation[0].custody_request_digest
                == artifact.request_digest
            ):
                return stored
            raise StorageProvenanceError("custody_artifact_conflict")
        if stored.object_revision != expected_object_revision:
            raise StorageProvenanceError("owner_object_revision_conflict")
        target_wrapped = OwnerWrappedDEK(
            artifact.target_encrypted_dek,
            target,
            rotation_id,
            artifact.request_digest,
        )
        return replace(
            stored,
            owner_wraps=stored.owner_wraps + (target_wrapped,),
            object_revision=stored.object_revision + 1,
        )

    def _build_owner_rewrap_request(
        self,
        stored: StoredObject,
        *,
        target_registration: AgentRecord,
        rotation_id: str,
        expected_object_revision: int,
    ) -> OwnerRewrapRequest:
        self._validate_stored_object(stored)
        source_registration = self.registry.resolve_active(stored.record.owner_aid)
        source = OwnerKeyProvenance.from_registration(source_registration)
        target = OwnerKeyProvenance.from_registration(target_registration)
        self._validate_rotation(
            source_registration,
            source,
            target_registration,
            target,
        )
        source_matches = [
            wrapped for wrapped in stored.owner_wraps if wrapped.provenance == source
        ]
        if len(source_matches) != 1:
            raise StorageProvenanceError("owner_provenance_mismatch")
        source_wrapped = source_matches[0]
        return OwnerRewrapRequest(
            backend=self.backend.name,
            rotation_id=rotation_id,
            owner_aid=stored.record.owner_aid,
            store_id=self.store_id,
            record_id=stored.record.record_id,
            expected_object_revision=expected_object_revision,
            source_registration_id=source_registration.registration_id,
            source_registration_version=source_registration.registration_version,
            source_public_key_fingerprint=source_registration.public_key_fingerprint,
            source_public_key=source_registration.public_key,
            target_registration_id=target_registration.registration_id,
            target_registration_version=target_registration.registration_version,
            target_public_key_fingerprint=target_registration.public_key_fingerprint,
            target_public_key=target_registration.public_key,
            source_encrypted_dek=source_wrapped.encrypted_dek,
            source_context=self.wrap_context(stored.record, source),
            target_context=self.wrap_context(stored.record, target),
        )

    def _cleanup_owner_rotation_object(
        self,
        stored: StoredObject,
        *,
        rotation_id: str,
        status: Literal["committed", "aborted"],
        source_registration_id: str,
        source_registration_version: int,
        target_registration: AgentRecord,
        original_object_revision: int,
    ) -> StoredObject:
        self._validate_stored_object(stored)
        if status not in ("committed", "aborted"):
            raise StorageProvenanceError("rotation_status_invalid")
        if not isinstance(original_object_revision, int) or original_object_revision < 1:
            raise StorageProvenanceError("owner_object_revision_conflict")
        target = OwnerKeyProvenance.from_registration(target_registration)
        staged = [
            wrapped
            for wrapped in stored.owner_wraps
            if wrapped.rotation_id == rotation_id and wrapped.provenance == target
        ]
        conflicting = [
            wrapped
            for wrapped in stored.owner_wraps
            if wrapped.rotation_id == rotation_id and wrapped.provenance != target
        ]
        if conflicting or len(staged) > 1:
            raise StorageProvenanceError("owner_rotation_conflict")

        source_matches = [
            wrapped
            for wrapped in stored.owner_wraps
            if (
                wrapped.provenance.owner_aid == target.owner_aid
                and wrapped.provenance.registration_id == source_registration_id
                and wrapped.provenance.registration_version == source_registration_version
            )
        ]
        if status == "aborted":
            if not staged:
                if stored.object_revision == original_object_revision:
                    return stored
                raise StorageProvenanceError("owner_object_revision_conflict")
            if stored.object_revision != original_object_revision + 1:
                raise StorageProvenanceError("owner_object_revision_conflict")
            remaining = tuple(
                wrapped
                for wrapped in stored.owner_wraps
                if not (
                    wrapped.rotation_id == rotation_id
                    and wrapped.provenance == target
                )
            )
        else:
            if not staged:
                raise StorageProvenanceError("owner_wrap_not_found")
            if not source_matches:
                if stored.object_revision == original_object_revision + 2:
                    return stored
                raise StorageProvenanceError("owner_object_revision_conflict")
            if len(source_matches) != 1 or stored.object_revision != original_object_revision + 1:
                raise StorageProvenanceError("owner_object_revision_conflict")
            remaining = tuple(
                wrapped for wrapped in stored.owner_wraps if wrapped not in source_matches
            )
        cleaned = replace(
            stored,
            owner_wraps=remaining,
            object_revision=stored.object_revision + 1,
        )
        self._validate_stored_object(cleaned)
        return cleaned

    @staticmethod
    def _validate_rotation(
        source_registration: AgentRecord,
        source: OwnerKeyProvenance,
        target_registration: AgentRecord,
        target: OwnerKeyProvenance,
    ) -> None:
        if source.owner_aid != target.owner_aid:
            raise StorageProvenanceError("rotation_owner_mismatch")
        if source.registration_id != target.registration_id:
            raise StorageProvenanceError("rotation_registration_id_mismatch")
        if target.registration_version != source.registration_version + 1:
            raise StorageProvenanceError("rotation_version_invalid")
        if hmac.compare_digest(
            source.public_key_fingerprint,
            target.public_key_fingerprint,
        ):
            raise StorageProvenanceError("rotation_key_unchanged")
        if source_registration.registered_by != target_registration.registered_by:
            raise StorageProvenanceError("rotation_actor_mismatch")

    @staticmethod
    def _aad(record: DataRecord) -> bytes:
        return (
            f"{record.owner_aid}|{record.record_id}|{record.data_class}|{record.version}"
        ).encode("utf-8")

    @staticmethod
    def _validate_stored_object(stored: StoredObject) -> None:
        if not isinstance(stored, StoredObject) or stored.schema_version != STORAGE_SCHEMA_VERSION:
            raise StorageProvenanceError("legacy_owner_wrap_unverified")
        if stored.object_revision < 1 or not stored.owner_wraps:
            raise StorageProvenanceError("owner_provenance_invalid")
        for wrapped in stored.owner_wraps:
            digest = wrapped.custody_request_digest
            if digest is not None and (not isinstance(digest, bytes) or len(digest) != 32):
                raise StorageProvenanceError("owner_provenance_invalid")
            if wrapped.rotation_id is None and digest is not None:
                raise StorageProvenanceError("owner_provenance_invalid")
            if (
                not isinstance(wrapped.encrypted_dek, bytes)
                or not wrapped.encrypted_dek
                or wrapped.provenance.owner_aid != stored.record.owner_aid
            ):
                raise StorageProvenanceError("owner_provenance_invalid")

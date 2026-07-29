"""MongoDB-backed registration-bound encrypted object storage."""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict
from typing import Any, Literal

from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from presaga.crypto import envelope
from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.registry import AgentRecord, AgentRegistry
from presaga.storage.encrypted_store import (
    STORAGE_SCHEMA_VERSION,
    EncryptedStore,
    OwnerKeyProvenance,
    OwnerWrappedDEK,
    StoredObject,
    StorageProvenanceError,
)


class MongoEncryptedStore(EncryptedStore):
    """Persist v2 encrypted objects with per-document CAS semantics.

    This class does not claim multi-document transactionality. Rotation
    coordination must stage every target wrap before the registration CAS.
    """

    def __init__(
        self,
        backend: PREBackend,
        db: Database,
        registry: AgentRegistry,
        *,
        collection_name: str = "encrypted_objects",
    ):
        super().__init__(
            backend,
            registry,
            store_id=f"mongo:{db.name}.{collection_name}",
        )
        self.collection = db[collection_name]
        self.collection.create_index("record.record_id", unique=True)
        self.collection.create_index(
            [("record.owner_aid", 1), ("object_revision", 1)],
            name="owner_object_revision",
        )

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
        try:
            self.collection.insert_one(self._serialize(stored))
        except DuplicateKeyError as error:
            raise StorageProvenanceError("stored_object_exists") from error
        return stored

    def get(self, record_id: str) -> StoredObject:
        document = self.collection.find_one({"record.record_id": record_id})
        if document is None:
            raise KeyError(record_id)
        return self._deserialize(document)

    def has_owner_objects(self, owner_aid: str) -> bool:
        return self.collection.find_one(
            {"record.owner_aid": owner_aid},
            {"_id": 1},
        ) is not None

    def owner_object_revisions(self, owner_aid: str) -> dict[str, int]:
        documents = self.collection.find(
            {"record.owner_aid": owner_aid},
            {"record.record_id": 1, "object_revision": 1, "schema_version": 1},
        ).sort("record.record_id", 1)
        revisions: dict[str, int] = {}
        for document in documents:
            if document.get("schema_version") != STORAGE_SCHEMA_VERSION:
                raise StorageProvenanceError("legacy_owner_wrap_unverified")
            try:
                revisions[str(document["record"]["record_id"])] = int(
                    document["object_revision"]
                )
            except (KeyError, TypeError, ValueError) as error:
                raise StorageProvenanceError("owner_provenance_invalid") from error
        return revisions

    def snapshot(self) -> tuple[StoredObject, ...]:
        documents = self.collection.find({}).sort("record.record_id", 1)
        return tuple(self._deserialize(document) for document in documents)

    def restore(self, stored: StoredObject) -> None:
        self._validate_stored_object(stored)
        if stored.ciphertext.aad != self._aad(stored.record):
            raise StorageProvenanceError("stored_object_aad_mismatch")
        try:
            self.collection.insert_one(self._serialize(stored))
        except DuplicateKeyError as error:
            raise StorageProvenanceError("stored_object_exists") from error

    def stage_owner_rewrap(
        self,
        record_id: str,
        target_registration: AgentRecord,
        source_private_key: bytes,
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
                source_private_key=source_private_key,
                rotation_id=rotation_id,
                expected_object_revision=expected_object_revision,
            )
            if staged is stored:
                return stored
            result = self.collection.replace_one(
                {
                    "record.record_id": record_id,
                    "schema_version": STORAGE_SCHEMA_VERSION,
                    "object_revision": expected_object_revision,
                },
                self._serialize(staged),
                upsert=False,
            )
            if result.matched_count != 1:
                raise StorageProvenanceError("owner_object_revision_conflict")
            return staged

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
        """Apply cleanup with a server-side object-revision compare-and-swap."""
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
            if cleaned is stored:
                return stored
            result = self.collection.replace_one(
                {
                    "record.record_id": record_id,
                    "schema_version": STORAGE_SCHEMA_VERSION,
                    "object_revision": stored.object_revision,
                },
                self._serialize(cleaned),
                upsert=False,
            )
            if result.matched_count != 1:
                raise StorageProvenanceError("owner_object_revision_conflict")
            return cleaned

    def _serialize(self, stored: StoredObject) -> dict[str, Any]:
        self._validate_stored_object(stored)
        return {
            "schema_version": stored.schema_version,
            "object_revision": stored.object_revision,
            "record": asdict(stored.record),
            "ciphertext": stored.ciphertext.to_dict(),
            "owner_wraps": [
                {
                    "encrypted_dek_b64": _b64(wrapped.encrypted_dek),
                    "provenance": asdict(wrapped.provenance),
                    "rotation_id": wrapped.rotation_id,
                }
                for wrapped in stored.owner_wraps
            ],
            "provider_plaintext_data_visible": False,
            "provider_plaintext_dek_visible": False,
        }

    def _deserialize(self, document: dict[str, Any]) -> StoredObject:
        if document.get("schema_version") != STORAGE_SCHEMA_VERSION:
            raise StorageProvenanceError("legacy_owner_wrap_unverified")
        try:
            record = DataRecord(**document["record"])
            ciphertext = envelope.EnvelopeCiphertext.from_dict(document["ciphertext"])
            wraps = tuple(
                OwnerWrappedDEK(
                    encrypted_dek=_unb64(raw["encrypted_dek_b64"]),
                    provenance=OwnerKeyProvenance(**raw["provenance"]),
                    rotation_id=raw.get("rotation_id"),
                )
                for raw in document["owner_wraps"]
            )
            stored = StoredObject(
                record=record,
                ciphertext=ciphertext,
                owner_wraps=wraps,
                object_revision=int(document["object_revision"]),
                schema_version=int(document["schema_version"]),
            )
            self._validate_stored_object(stored)
            if stored.ciphertext.aad != self._aad(stored.record):
                raise StorageProvenanceError("stored_object_aad_mismatch")
            return stored
        except StorageProvenanceError:
            raise
        except (
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise StorageProvenanceError("owner_provenance_invalid") from error


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Base64 stored-object field must be text")
    return base64.b64decode(value.encode("ascii"), validate=True)

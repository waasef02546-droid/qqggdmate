"""Encrypted in-memory data store."""

from __future__ import annotations

from dataclasses import dataclass

from presaga.crypto import envelope
from presaga.crypto.key_rotation import data_context
from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataRecord


@dataclass
class StoredObject:
    record: DataRecord
    ciphertext: envelope.EnvelopeCiphertext
    encrypted_dek_owner: bytes


class EncryptedStore:
    def __init__(self, backend: PREBackend):
        self.backend = backend
        self._objects: dict[str, StoredObject] = {}

    def put(self, record: DataRecord, plaintext: bytes, owner_public_key: bytes) -> StoredObject:
        dek = envelope.generate_dek()
        aad = self._aad(record)
        ciphertext = envelope.encrypt(plaintext, dek, aad)
        encrypted_dek_owner = self.backend.wrap_dek(dek, owner_public_key, self.context(record))
        stored = StoredObject(record=record, ciphertext=ciphertext, encrypted_dek_owner=encrypted_dek_owner)
        self._objects[record.record_id] = stored
        return stored

    def get(self, record_id: str) -> StoredObject:
        return self._objects[record_id]

    def decrypt_with_dek(self, stored: StoredObject, dek: bytes) -> bytes:
        return envelope.decrypt(stored.ciphertext, dek)

    def context(self, record: DataRecord) -> bytes:
        return data_context(record.owner_aid, record.record_id, record.data_class, record.version)

    def _aad(self, record: DataRecord) -> bytes:
        return f"{record.owner_aid}|{record.record_id}|{record.data_class}|{record.version}".encode("utf-8")

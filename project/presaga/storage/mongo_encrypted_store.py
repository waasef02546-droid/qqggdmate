"""MongoDB-backed encrypted object store for PRE-SAGA E2E experiments."""

from __future__ import annotations

import base64
from dataclasses import asdict
from typing import Any

from pymongo.database import Database

from presaga.crypto import envelope
from presaga.crypto.key_rotation import data_context
from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataRecord
from presaga.storage.encrypted_store import StoredObject


class MongoEncryptedStore:
    """Persist encrypted records and owner-wrapped DEKs in MongoDB.

    The Provider only stores ciphertext and encrypted DEKs. Plaintext is never
    written to MongoDB by this class.
    """

    def __init__(self, backend: PREBackend, db: Database, *, collection_name: str = "encrypted_objects"):
        self.backend = backend
        self.collection = db[collection_name]
        self.collection.create_index("record.record_id", unique=True)

    def put(self, record: DataRecord, plaintext: bytes, owner_public_key: bytes) -> StoredObject:
        dek = envelope.generate_dek()
        aad = self._aad(record)
        ciphertext = envelope.encrypt(plaintext, dek, aad)
        encrypted_dek_owner = self.backend.wrap_dek(dek, owner_public_key, self.context(record))
        stored = StoredObject(record=record, ciphertext=ciphertext, encrypted_dek_owner=encrypted_dek_owner)
        self.collection.replace_one(
            {"record.record_id": record.record_id},
            self._serialize(stored),
            upsert=True,
        )
        return stored

    def get(self, record_id: str) -> StoredObject:
        document = self.collection.find_one({"record.record_id": record_id})
        if document is None:
            raise KeyError(record_id)
        return self._deserialize(document)

    def decrypt_with_dek(self, stored: StoredObject, dek: bytes) -> bytes:
        return envelope.decrypt(stored.ciphertext, dek)

    def context(self, record: DataRecord) -> bytes:
        return data_context(record.owner_aid, record.record_id, record.data_class, record.version)

    def _aad(self, record: DataRecord) -> bytes:
        return f"{record.owner_aid}|{record.record_id}|{record.data_class}|{record.version}".encode("utf-8")

    def _serialize(self, stored: StoredObject) -> dict[str, Any]:
        return {
            "record": asdict(stored.record),
            "ciphertext": {
                "nonce": _b64(stored.ciphertext.nonce),
                "ciphertext": _b64(stored.ciphertext.ciphertext),
                "tag": _b64(stored.ciphertext.tag),
                "aad": _b64(stored.ciphertext.aad),
            },
            "encrypted_dek_owner": _b64(stored.encrypted_dek_owner),
            "provider_plaintext_data_visible": False,
            "provider_plaintext_dek_visible": False,
        }

    def _deserialize(self, document: dict[str, Any]) -> StoredObject:
        record = DataRecord(**document["record"])
        ciphertext_doc = document["ciphertext"]
        ciphertext = envelope.EnvelopeCiphertext(
            nonce=_unb64(ciphertext_doc["nonce"]),
            ciphertext=_unb64(ciphertext_doc["ciphertext"]),
            tag=_unb64(ciphertext_doc["tag"]),
            aad=_unb64(ciphertext_doc["aad"]),
        )
        return StoredObject(
            record=record,
            ciphertext=ciphertext,
            encrypted_dek_owner=_unb64(document["encrypted_dek_owner"]),
        )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))

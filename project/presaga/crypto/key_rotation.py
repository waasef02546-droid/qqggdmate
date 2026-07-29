"""Domain-separated contexts for data and owner-key lifecycle operations."""

from __future__ import annotations

import hashlib
import json
from typing import Protocol


class OwnerProvenance(Protocol):
    @property
    def owner_aid(self) -> str: ...

    @property
    def registration_id(self) -> str: ...

    @property
    def registration_version(self) -> int: ...

    @property
    def public_key_fingerprint(self) -> str: ...

    @property
    def key_algorithm(self) -> str: ...


def data_context(owner_aid: str, record_id: str, data_class: str, version: int) -> bytes:
    material = f"{owner_aid}|{record_id}|{data_class}|{version}".encode("utf-8")
    return hashlib.sha256(material).digest()


def owner_wrap_context(data_binding: bytes, provenance: OwnerProvenance) -> bytes:
    """Bind an owner-wrapped DEK to one exact registration generation."""
    payload = {
        "data_context": data_binding.hex(),
        "key_algorithm": provenance.key_algorithm,
        "owner_aid": provenance.owner_aid,
        "public_key_fingerprint": provenance.public_key_fingerprint,
        "registration_id": provenance.registration_id,
        "registration_version": provenance.registration_version,
    }
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"presaga-owner-wrap-v1\x00" + normalized).digest()

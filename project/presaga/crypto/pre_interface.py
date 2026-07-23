"""Proxy re-encryption backend interface.

The bundled implementations are intentionally non-production stubs.  This
interface is the seam where a reviewed PRE or HPKE-based key-sharing adapter
must be integrated before any real deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    private_key: bytes


class PREBackend(Protocol):
    name: str

    def generate_keypair(self) -> KeyPair:
        ...

    def wrap_dek(self, dek: bytes, public_key: bytes, context: bytes) -> bytes:
        ...

    def unwrap_dek(self, encrypted_dek: bytes, private_key: bytes, context: bytes) -> bytes:
        ...

    def generate_rekey(self, owner_private_key: bytes, requester_public_key: bytes, context: bytes) -> bytes:
        ...

    def transform(self, encrypted_dek: bytes, rekey: bytes) -> bytes:
        ...

"""Proxy re-encryption backend interface.

The bundled implementations are intentionally non-production stubs.  This
interface is the seam where a reviewed PRE or HPKE-based key-sharing adapter
must be integrated before any real deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class PREBackendError(Exception):
    """Stable base exception for PRE backend failures."""


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    private_key: bytes


class PREBackend(Protocol):
    name: str

    def generate_keypair(self) -> KeyPair:
        ...

    def public_key_from_private(self, private_key: bytes) -> bytes:
        """Derive the public key so rotation can reject the wrong source key."""
        ...

    def wrap_dek(self, dek: bytes, public_key: bytes, context: bytes) -> bytes:
        ...

    def unwrap_dek(self, encrypted_dek: bytes, private_key: bytes, context: bytes) -> bytes:
        ...

    def generate_rekey(self, owner_private_key: bytes, requester_public_key: bytes, context: bytes) -> bytes:
        ...

    def transform(
        self,
        encrypted_dek: bytes,
        rekey: bytes,
        *,
        context: bytes | None = None,
        requester_public_key: bytes | None = None,
    ) -> bytes:
        """Transform a wrapped DEK under server-supplied binding inputs."""
        ...

    def rewrap_dek(
        self,
        encrypted_dek: bytes,
        source_private_key: bytes,
        target_public_key: bytes,
        source_context: bytes,
        target_context: bytes,
    ) -> bytes:
        """Prototype seam for owner-to-owner rewrap without returning a plaintext DEK.

        The bundled implementations remain insecure control-flow stubs. A real
        adapter must replace this with an authenticated owner/KMS operation.
        """
        ...

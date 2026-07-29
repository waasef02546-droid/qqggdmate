"""INSECURE HPKE/KEM-shaped compatibility stub.

This module separates protocol logic from the toy PRE backend. It mimics a KEM
wrapping interface for tests and future adapter work, but it is not a production
HPKE implementation, is not interoperable with HPKE, and must never protect
real keys or data.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from presaga.crypto.pre_interface import KeyPair


class HPKEKEMStub:
    name = "hpke-kem-stub"

    def generate_keypair(self) -> KeyPair:
        private_key = os.urandom(32)
        public_key = hashlib.sha256(b"hpke-stub" + private_key).digest()
        return KeyPair(public_key=public_key, private_key=private_key)

    def public_key_from_private(self, private_key: bytes) -> bytes:
        return hashlib.sha256(b"hpke-stub" + private_key).digest()

    def _stream(self, public_key: bytes, context: bytes, size: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < size:
            out.extend(hmac.new(public_key, b"kem-wrap" + context + counter.to_bytes(4, "big"), hashlib.sha256).digest())
            counter += 1
        return bytes(out[:size])

    def wrap_dek(self, dek: bytes, public_key: bytes, context: bytes) -> bytes:
        stream = self._stream(public_key, context, len(dek))
        return bytes(left ^ right for left, right in zip(dek, stream))

    def unwrap_dek(self, encrypted_dek: bytes, private_key: bytes, context: bytes) -> bytes:
        return self.wrap_dek(encrypted_dek, self.public_key_from_private(private_key), context)

    def generate_rekey(self, owner_private_key: bytes, requester_public_key: bytes, context: bytes) -> bytes:
        owner_stream = self._stream(self.public_key_from_private(owner_private_key), context, 32)
        requester_stream = self._stream(requester_public_key, context, 32)
        return bytes(left ^ right for left, right in zip(owner_stream, requester_stream))

    def transform(self, encrypted_dek: bytes, rekey: bytes) -> bytes:
        if len(encrypted_dek) != len(rekey):
            raise ValueError("encrypted DEK and rekey must have equal length")
        return bytes(left ^ right for left, right in zip(encrypted_dek, rekey))

    def rewrap_dek(
        self,
        encrypted_dek: bytes,
        source_private_key: bytes,
        target_public_key: bytes,
        source_context: bytes,
        target_context: bytes,
    ) -> bytes:
        """INSECURE deterministic owner rewrap for lifecycle testing only."""
        source_stream = self._stream(
            self.public_key_from_private(source_private_key),
            source_context,
            len(encrypted_dek),
        )
        target_stream = self._stream(target_public_key, target_context, len(encrypted_dek))
        return bytes(
            wrapped ^ source ^ target
            for wrapped, source, target in zip(encrypted_dek, source_stream, target_stream)
        )

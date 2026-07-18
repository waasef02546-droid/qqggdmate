"""HPKE/KEM-style wrapping stub.

This module separates protocol logic from the toy PRE backend. It mimics a KEM
wrapping interface for tests and future adapter work, but it is not a production
HPKE implementation.
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

    def _public_from_private(self, private_key: bytes) -> bytes:
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
        return self.wrap_dek(encrypted_dek, self._public_from_private(private_key), context)

    def generate_rekey(self, owner_private_key: bytes, requester_public_key: bytes, context: bytes) -> bytes:
        owner_stream = self._stream(self._public_from_private(owner_private_key), context, 32)
        requester_stream = self._stream(requester_public_key, context, 32)
        return bytes(left ^ right for left, right in zip(owner_stream, requester_stream))

    def transform(self, encrypted_dek: bytes, rekey: bytes) -> bytes:
        if len(encrypted_dek) != len(rekey):
            raise ValueError("encrypted DEK and rekey must have equal length")
        return bytes(left ^ right for left, right in zip(encrypted_dek, rekey))

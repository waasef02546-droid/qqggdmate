"""INSECURE toy PRE backend used only for protocol-level tests.

The transform works by XORing an owner-wrapped DEK with a rekey delta so that
the result can be unwrapped by the requester key. The proxy only receives the
owner-wrapped DEK and rekey delta; it does not need plaintext DEK.

This backend is not a secure PRE construction, does not provide a security
proof, and must never protect real keys or data.  Its sole purpose is to keep
the policy/token/transform control-flow testable while a real PRE/HPKE adapter
is selected and integrated.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from presaga.crypto.pre_interface import KeyPair


class ToyPRE:
    name = "toy-pre"

    def generate_keypair(self) -> KeyPair:
        private_key = os.urandom(32)
        public_key = hashlib.sha256(private_key).digest()
        return KeyPair(public_key=public_key, private_key=private_key)

    def _public_from_private(self, private_key: bytes) -> bytes:
        return hashlib.sha256(private_key).digest()

    def _mask(self, public_key: bytes, context: bytes, size: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < size:
            output.extend(hmac.new(public_key, context + counter.to_bytes(4, "big"), hashlib.sha256).digest())
            counter += 1
        return bytes(output[:size])

    def _xor(self, left: bytes, right: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(left, right))

    def wrap_dek(self, dek: bytes, public_key: bytes, context: bytes) -> bytes:
        return self._xor(dek, self._mask(public_key, context, len(dek)))

    def unwrap_dek(self, encrypted_dek: bytes, private_key: bytes, context: bytes) -> bytes:
        public_key = self._public_from_private(private_key)
        return self._xor(encrypted_dek, self._mask(public_key, context, len(encrypted_dek)))

    def generate_rekey(self, owner_private_key: bytes, requester_public_key: bytes, context: bytes) -> bytes:
        owner_public_key = self._public_from_private(owner_private_key)
        owner_mask = self._mask(owner_public_key, context, 32)
        requester_mask = self._mask(requester_public_key, context, 32)
        return self._xor(owner_mask, requester_mask)

    def transform(self, encrypted_dek: bytes, rekey: bytes) -> bytes:
        if len(encrypted_dek) != len(rekey):
            raise ValueError("encrypted DEK and rekey must have equal length")
        return self._xor(encrypted_dek, rekey)

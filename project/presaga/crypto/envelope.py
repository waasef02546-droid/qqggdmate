"""Envelope encryption helpers for the PRE-SAGA prototype.

This module uses a small HMAC-derived stream construction to keep the prototype
self-contained. It is suitable for protocol tests only and must be replaced by
an audited AEAD implementation in a production system.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


DEK_SIZE = 32
NONCE_SIZE = 16
TAG_SIZE = 32


@dataclass(frozen=True)
class EnvelopeCiphertext:
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes


def generate_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def _stream(key: bytes, nonce: bytes, size: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:size])


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(plaintext: bytes, dek: bytes, aad: bytes = b"") -> EnvelopeCiphertext:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = _xor(plaintext, _stream(dek, nonce, len(plaintext)))
    tag = hmac.new(dek, aad + nonce + ciphertext, hashlib.sha256).digest()
    return EnvelopeCiphertext(nonce=nonce, ciphertext=ciphertext, tag=tag, aad=aad)


def decrypt(envelope: EnvelopeCiphertext, dek: bytes) -> bytes:
    expected = hmac.new(dek, envelope.aad + envelope.nonce + envelope.ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, envelope.tag):
        raise ValueError("envelope authentication failed")
    return _xor(envelope.ciphertext, _stream(dek, envelope.nonce, len(envelope.ciphertext)))

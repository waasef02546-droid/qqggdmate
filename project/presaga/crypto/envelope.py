"""AES-256-GCM envelope encryption for the PRE-SAGA prototype.

The encrypted payload is authenticated together with caller-supplied associated
data (AAD).  PRE-SAGA stores record identity, owner, class, and version in AAD,
so ciphertext cannot be moved to a different record without detection.

Only the data-encryption layer in this module is production-grade primitive
usage.  It does *not* make the prototype PRE backends production-safe; see
``toy_pre.py`` and ``hpke_kem_stub.py``.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover - exercised only in unsupported deployments
    raise RuntimeError(
        "PRE-SAGA envelope encryption requires the 'cryptography' package with AESGCM support. "
        "No unaudited crypto fallback is provided."
    ) from exc


DEK_SIZE = 32
NONCE_SIZE = 12  # NIST-recommended AES-GCM nonce size
TAG_SIZE = 16
ENVELOPE_VERSION = 1
ENVELOPE_ALGORITHM = "AES-256-GCM"


class EnvelopeAuthenticationError(ValueError):
    """Raised when an envelope cannot be authenticated or is malformed."""


@dataclass(frozen=True)
class EnvelopeCiphertext:
    """Portable AES-GCM envelope components.

    ``to_dict``/``from_dict`` use Base64 strings and explicit version/algorithm
    fields so an envelope can safely cross process and persistence boundaries.
    """

    nonce: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes
    version: int = ENVELOPE_VERSION
    algorithm: str = ENVELOPE_ALGORITHM

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable, versioned envelope representation."""
        _validate_envelope(self)
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "nonce_b64": _b64(self.nonce),
            "ciphertext_b64": _b64(self.ciphertext),
            "tag_b64": _b64(self.tag),
            "aad_b64": _b64(self.aad),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EnvelopeCiphertext":
        """Decode a versioned envelope created by :meth:`to_dict`."""
        try:
            envelope = cls(
                nonce=_unb64(value["nonce_b64"]),
                ciphertext=_unb64(value["ciphertext_b64"]),
                tag=_unb64(value["tag_b64"]),
                aad=_unb64(value["aad_b64"]),
                version=int(value["version"]),
                algorithm=str(value["algorithm"]),
            )
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise EnvelopeAuthenticationError("invalid envelope encoding") from exc
        _validate_envelope(envelope)
        return envelope


def generate_dek() -> bytes:
    """Generate a fresh 256-bit data-encryption key."""
    return os.urandom(DEK_SIZE)


def encrypt(plaintext: bytes, dek: bytes, aad: bytes = b"") -> EnvelopeCiphertext:
    """Encrypt *plaintext* with a fresh nonce and bind it to *aad*."""
    _validate_key(dek)
    _validate_bytes("plaintext", plaintext)
    _validate_bytes("aad", aad)
    nonce = os.urandom(NONCE_SIZE)
    encrypted = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return EnvelopeCiphertext(
        nonce=nonce,
        ciphertext=encrypted[:-TAG_SIZE],
        tag=encrypted[-TAG_SIZE:],
        aad=aad,
    )


def decrypt(envelope: EnvelopeCiphertext, dek: bytes, aad: bytes | None = None) -> bytes:
    """Authenticate and decrypt an envelope.

    If ``aad`` is supplied, it must exactly match the embedded AAD.  All
    malformed, wrong-key, tampered, and AAD-mismatch cases intentionally raise
    the same public error to avoid exposing authentication details.
    """
    _validate_key(dek)
    try:
        _validate_envelope(envelope)
        if aad is not None:
            _validate_bytes("aad", aad)
            if aad != envelope.aad:
                raise EnvelopeAuthenticationError("envelope authentication failed")
        return AESGCM(dek).decrypt(envelope.nonce, envelope.ciphertext + envelope.tag, envelope.aad)
    except (InvalidTag, TypeError, ValueError) as exc:
        if isinstance(exc, EnvelopeAuthenticationError):
            raise
        raise EnvelopeAuthenticationError("envelope authentication failed") from exc


def _validate_key(dek: bytes) -> None:
    _validate_bytes("dek", dek)
    if len(dek) != DEK_SIZE:
        raise ValueError(f"dek must be exactly {DEK_SIZE} bytes for AES-256-GCM")


def _validate_envelope(envelope: EnvelopeCiphertext) -> None:
    if not isinstance(envelope, EnvelopeCiphertext):
        raise EnvelopeAuthenticationError("invalid envelope encoding")
    if envelope.version != ENVELOPE_VERSION or envelope.algorithm != ENVELOPE_ALGORITHM:
        raise EnvelopeAuthenticationError("unsupported envelope format")
    for name, value in (("nonce", envelope.nonce), ("ciphertext", envelope.ciphertext), ("tag", envelope.tag), ("aad", envelope.aad)):
        try:
            _validate_bytes(name, value)
        except ValueError as exc:
            raise EnvelopeAuthenticationError("invalid envelope encoding") from exc
    if len(envelope.nonce) != NONCE_SIZE or len(envelope.tag) != TAG_SIZE:
        raise EnvelopeAuthenticationError("invalid envelope encoding")


def _validate_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Base64 envelope field must be text")
    return base64.b64decode(value.encode("ascii"), validate=True)

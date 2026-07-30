"""Concrete 1-of-1 Umbral PRE backend.

The backend delegates Umbral cryptography to ``nucypher-core`` and adds a
versioned PRE-SAGA envelope.  The envelope and the encrypted plaintext both
bind a wrapped DEK to its caller-supplied context.  Re-encryption key
fragments sign and verify both delegating and receiving public keys.

``rewrap_dek`` is deliberately a trusted management-plane operation: it
decrypts the source wrapper inside this process and creates a fresh target
wrapper.  It is not a proxy transformation and must be placed behind the
trusted owner/KMS boundary in a deployment.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable

from nucypher_core import MessageKit
from nucypher_core.umbral import (
    CapsuleFrag,
    KeyFrag,
    PublicKey,
    SecretKey,
    Signer,
    generate_kfrags,
    reencrypt,
)

from presaga.crypto.pre_interface import KeyPair, PREBackendError


class UmbralFormatError(PREBackendError):
    """An Umbral PRE envelope or key has an invalid representation."""


class UmbralValidationError(PREBackendError):
    """An Umbral PRE object does not match the trusted binding inputs."""


class UmbralDecryptionError(PREBackendError):
    """An Umbral PRE ciphertext cannot be decrypted by the supplied key."""


_MAGIC = b"PSGP"
_SUITE = 1
_VERSION = 1
_OWNER_WRAPPER = 1
_REKEY = 2
_TRANSFORMED_WRAPPER = 3
_HEADER = struct.Struct(">4sBBBI")
_FIELD_LENGTH = struct.Struct(">I")
_CONTEXT_DIGEST_SIZE = 32
_DEK_SIZE = 32
_PUBLIC_KEY_SIZE = 33
_PLAINTEXT_DOMAIN = b"PRE-SAGA/UMBRAL-DEK/V1\x00"
_MAX_FIELD_SIZE = 1 << 20


def _context_digest(context: bytes) -> bytes:
    if not isinstance(context, bytes):
        raise UmbralValidationError("context_must_be_bytes")
    return hashlib.sha256(context).digest()


def _encode_fields(fields: Iterable[bytes]) -> bytes:
    output = bytearray()
    for field in fields:
        if not isinstance(field, bytes):
            raise UmbralFormatError("envelope_field_must_be_bytes")
        if len(field) > _MAX_FIELD_SIZE:
            raise UmbralFormatError("envelope_field_too_large")
        output.extend(_FIELD_LENGTH.pack(len(field)))
        output.extend(field)
    return bytes(output)


def _decode_fields(payload: bytes, expected_count: int) -> tuple[bytes, ...]:
    fields: list[bytes] = []
    offset = 0
    for _ in range(expected_count):
        if len(payload) - offset < _FIELD_LENGTH.size:
            raise UmbralFormatError("envelope_field_length_missing")
        (length,) = _FIELD_LENGTH.unpack_from(payload, offset)
        offset += _FIELD_LENGTH.size
        if length > _MAX_FIELD_SIZE:
            raise UmbralFormatError("envelope_field_too_large")
        end = offset + length
        if end > len(payload):
            raise UmbralFormatError("envelope_field_truncated")
        fields.append(payload[offset:end])
        offset = end
    if offset != len(payload):
        raise UmbralFormatError("envelope_trailing_data")
    return tuple(fields)


def _pack(kind: int, fields: Iterable[bytes]) -> bytes:
    payload = _encode_fields(fields)
    return _HEADER.pack(_MAGIC, _SUITE, _VERSION, kind, len(payload)) + payload


def _unpack(data: bytes, expected_kind: int | None = None) -> tuple[int, bytes]:
    if not isinstance(data, bytes):
        raise UmbralFormatError("envelope_must_be_bytes")
    if len(data) < _HEADER.size:
        raise UmbralFormatError("envelope_header_truncated")
    magic, suite, version, kind, payload_length = _HEADER.unpack_from(data)
    if magic != _MAGIC:
        raise UmbralFormatError("envelope_magic_invalid")
    if suite != _SUITE:
        raise UmbralFormatError("envelope_suite_unsupported")
    if version != _VERSION:
        raise UmbralFormatError("envelope_version_unsupported")
    if kind not in {_OWNER_WRAPPER, _REKEY, _TRANSFORMED_WRAPPER}:
        raise UmbralFormatError("envelope_kind_unsupported")
    if expected_kind is not None and kind != expected_kind:
        raise UmbralFormatError("envelope_kind_unexpected")
    payload = data[_HEADER.size :]
    if payload_length != len(payload):
        raise UmbralFormatError("envelope_length_mismatch")
    return kind, payload


def _parse_public_key(data: bytes) -> PublicKey:
    if len(data) != _PUBLIC_KEY_SIZE:
        raise UmbralFormatError("public_key_length_invalid")
    try:
        return PublicKey.from_compressed_bytes(data)
    except Exception as exc:
        raise UmbralFormatError("public_key_invalid") from exc


def _parse_private_key(data: bytes) -> SecretKey:
    if not isinstance(data, bytes):
        raise UmbralFormatError("private_key_must_be_bytes")
    try:
        return SecretKey.from_be_bytes(data)
    except Exception as exc:
        raise UmbralFormatError("private_key_invalid") from exc


def _parse_message_kit(data: bytes) -> MessageKit:
    try:
        return MessageKit.from_bytes(data)
    except Exception as exc:
        raise UmbralFormatError("message_kit_invalid") from exc


def _decode_plaintext(
    plaintext: bytes,
    context_digest: bytes,
    owner_public_key: bytes,
) -> bytes:
    prefix_size = (
        len(_PLAINTEXT_DOMAIN)
        + _CONTEXT_DIGEST_SIZE
        + _PUBLIC_KEY_SIZE
    )
    if len(plaintext) != prefix_size + _DEK_SIZE:
        raise UmbralValidationError("dek_plaintext_length_invalid")
    if plaintext[: len(_PLAINTEXT_DOMAIN)] != _PLAINTEXT_DOMAIN:
        raise UmbralValidationError("dek_plaintext_domain_invalid")
    digest_end = len(_PLAINTEXT_DOMAIN) + _CONTEXT_DIGEST_SIZE
    if plaintext[len(_PLAINTEXT_DOMAIN) : digest_end] != context_digest:
        raise UmbralValidationError("dek_plaintext_context_mismatch")
    if plaintext[digest_end:prefix_size] != owner_public_key:
        raise UmbralValidationError("dek_plaintext_owner_key_mismatch")
    return plaintext[prefix_size:]


class UmbralPREBackend:
    """A concrete Umbral PRE backend with 1-of-1 re-encryption fragments."""

    name = "umbral-pre-v1"
    dependency_distribution = "nucypher-core"
    dependency_version = "0.15.0"
    adapter_format_version = _VERSION
    threshold = 1
    shares = 1

    def generate_keypair(self) -> KeyPair:
        private_key = SecretKey.random()
        return KeyPair(
            public_key=private_key.public_key().to_compressed_bytes(),
            private_key=private_key.to_be_bytes(),
        )

    def public_key_from_private(self, private_key: bytes) -> bytes:
        return _parse_private_key(private_key).public_key().to_compressed_bytes()

    def wrap_dek(self, dek: bytes, public_key: bytes, context: bytes) -> bytes:
        if not isinstance(dek, bytes) or len(dek) != _DEK_SIZE:
            raise UmbralValidationError("dek_must_be_32_bytes")
        digest = _context_digest(context)
        owner_key = _parse_public_key(public_key)
        try:
            message_kit = MessageKit(
                owner_key,
                _PLAINTEXT_DOMAIN + digest + public_key + dek,
                None,
            )
        except Exception as exc:
            raise PREBackendError("umbral_encryption_failed") from exc
        return _pack(_OWNER_WRAPPER, (digest, public_key, bytes(message_kit)))

    def unwrap_dek(
        self,
        encrypted_dek: bytes,
        private_key: bytes,
        context: bytes,
    ) -> bytes:
        kind, payload = _unpack(encrypted_dek)
        digest = _context_digest(context)
        secret_key = _parse_private_key(private_key)
        supplied_public_key = secret_key.public_key().to_compressed_bytes()

        if kind == _OWNER_WRAPPER:
            envelope_digest, owner_public_key, message_kit_bytes = _decode_fields(payload, 3)
            self._validate_digest(envelope_digest, digest)
            _parse_public_key(owner_public_key)
            if owner_public_key != supplied_public_key:
                raise UmbralValidationError("owner_private_key_mismatch")
            message_kit = _parse_message_kit(message_kit_bytes)
            try:
                plaintext = message_kit.decrypt(secret_key)
            except Exception as exc:
                raise UmbralDecryptionError("owner_decryption_failed") from exc
            return _decode_plaintext(plaintext, digest, owner_public_key)

        if kind == _TRANSFORMED_WRAPPER:
            (
                envelope_digest,
                owner_public_key,
                requester_public_key,
                verifying_public_key,
                message_kit_bytes,
                capsule_frag_bytes,
            ) = _decode_fields(payload, 6)
            self._validate_digest(envelope_digest, digest)
            owner_key = _parse_public_key(owner_public_key)
            requester_key = _parse_public_key(requester_public_key)
            verifying_key = _parse_public_key(verifying_public_key)
            if requester_public_key != supplied_public_key:
                raise UmbralValidationError("requester_private_key_mismatch")
            message_kit = _parse_message_kit(message_kit_bytes)
            try:
                capsule_frag = CapsuleFrag.from_bytes(capsule_frag_bytes)
                verified_frag = capsule_frag.verify(
                    message_kit.capsule,
                    verifying_key,
                    owner_key,
                    requester_key,
                )
            except Exception as exc:
                raise UmbralValidationError("capsule_fragment_verification_failed") from exc
            try:
                plaintext = message_kit.decrypt_reencrypted(
                    secret_key,
                    owner_key,
                    [verified_frag],
                )
            except Exception as exc:
                raise UmbralDecryptionError("requester_decryption_failed") from exc
            return _decode_plaintext(plaintext, digest, owner_public_key)

        raise UmbralFormatError("envelope_kind_not_decryptable")

    def generate_rekey(
        self,
        owner_private_key: bytes,
        requester_public_key: bytes,
        context: bytes,
    ) -> bytes:
        digest = _context_digest(context)
        owner_secret_key = _parse_private_key(owner_private_key)
        owner_public_key = owner_secret_key.public_key().to_compressed_bytes()
        requester_key = _parse_public_key(requester_public_key)
        signing_key = SecretKey.random()
        signer = Signer(signing_key)
        try:
            verified_kfrag = generate_kfrags(
                owner_secret_key,
                requester_key,
                signer,
                threshold=1,
                shares=1,
                sign_delegating_key=True,
                sign_receiving_key=True,
            )[0]
        except Exception as exc:
            raise PREBackendError("rekey_generation_failed") from exc
        return _pack(
            _REKEY,
            (
                digest,
                owner_public_key,
                requester_public_key,
                signer.verifying_key().to_compressed_bytes(),
                bytes(verified_kfrag),
            ),
        )

    def transform(
        self,
        encrypted_dek: bytes,
        rekey: bytes,
        *,
        context: bytes | None = None,
        owner_public_key: bytes | None = None,
        requester_public_key: bytes | None = None,
    ) -> bytes:
        if context is None:
            raise UmbralValidationError("transform_context_required")
        if owner_public_key is None:
            raise UmbralValidationError("transform_owner_key_required")
        if requester_public_key is None:
            raise UmbralValidationError("transform_requester_key_required")
        trusted_digest = _context_digest(context)
        _parse_public_key(owner_public_key)
        trusted_requester = _parse_public_key(requester_public_key)

        _, owner_payload = _unpack(encrypted_dek, _OWNER_WRAPPER)
        owner_digest, wrapped_owner_public_key, message_kit_bytes = _decode_fields(
            owner_payload,
            3,
        )
        self._validate_digest(owner_digest, trusted_digest)
        if wrapped_owner_public_key != owner_public_key:
            raise UmbralValidationError("owner_registration_key_mismatch")
        owner_key = _parse_public_key(wrapped_owner_public_key)
        message_kit = _parse_message_kit(message_kit_bytes)

        _, rekey_payload = _unpack(rekey, _REKEY)
        (
            rekey_digest,
            rekey_owner_public_key,
            rekey_requester_public_key,
            verifying_public_key,
            key_frag_bytes,
        ) = _decode_fields(rekey_payload, 5)
        self._validate_digest(rekey_digest, trusted_digest)
        if rekey_owner_public_key != wrapped_owner_public_key:
            raise UmbralValidationError("rekey_owner_key_mismatch")
        if rekey_requester_public_key != requester_public_key:
            raise UmbralValidationError("rekey_requester_key_mismatch")
        verifying_key = _parse_public_key(verifying_public_key)
        _parse_public_key(rekey_owner_public_key)
        _parse_public_key(rekey_requester_public_key)
        try:
            key_frag = KeyFrag.from_bytes(key_frag_bytes)
            verified_kfrag = key_frag.verify(
                verifying_key,
                owner_key,
                trusted_requester,
            )
        except Exception as exc:
            raise UmbralValidationError("key_fragment_verification_failed") from exc
        try:
            verified_cfrag = reencrypt(message_kit.capsule, verified_kfrag)
        except Exception as exc:
            raise PREBackendError("reencryption_failed") from exc
        return _pack(
            _TRANSFORMED_WRAPPER,
            (
                trusted_digest,
                wrapped_owner_public_key,
                requester_public_key,
                verifying_public_key,
                message_kit_bytes,
                bytes(verified_cfrag),
            ),
        )

    def rewrap_dek(
        self,
        encrypted_dek: bytes,
        source_private_key: bytes,
        target_public_key: bytes,
        source_context: bytes,
        target_context: bytes,
    ) -> bytes:
        """Trusted management decrypt-and-fresh-encrypt rotation operation."""
        dek = self.unwrap_dek(encrypted_dek, source_private_key, source_context)
        return self.wrap_dek(dek, target_public_key, target_context)

    @staticmethod
    def _validate_digest(actual: bytes, expected: bytes) -> None:
        if len(actual) != _CONTEXT_DIGEST_SIZE:
            raise UmbralFormatError("context_digest_length_invalid")
        if actual != expected:
            raise UmbralValidationError("context_mismatch")

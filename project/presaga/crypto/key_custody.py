"""Authenticated owner/KMS boundary for owner-key rotation.

Only the custody implementation receives the source private key.  Provider-side
verification consumes a public, canonical request and an attested target wrapper.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

from nucypher_core.umbral import PublicKey, SecretKey, Signature, Signer

from presaga.crypto.pre_interface import PREBackendError
from presaga.crypto.umbral_pre import UmbralPREBackend


_REQUEST_DOMAIN = b"PRE-SAGA/OWNER-REWRAP-REQUEST/V1\x00"
_ATTESTATION_DOMAIN = b"PRE-SAGA/OWNER-REWRAP-ATTESTATION/V1\x00"
_SCHEMA_VERSION = 1
_CUSTODY_ALGORITHM = "umbral-owner-source-key-signature-v1"
_CUSTODY_VERSION = 1


class KeyCustodyError(Exception):
    """Stable custody failure with a machine-readable reason."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise KeyCustodyError("custody_payload_invalid")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise KeyCustodyError("custody_payload_invalid") from exc


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise KeyCustodyError("custody_request_invalid")
    return value


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise KeyCustodyError("custody_request_invalid")
    return value


@dataclass(frozen=True, slots=True)
class OwnerRewrapRequest:
    backend: str
    rotation_id: str
    owner_aid: str
    store_id: str
    record_id: str
    expected_object_revision: int
    source_registration_id: str
    source_registration_version: int
    source_public_key_fingerprint: str
    source_public_key: bytes
    target_registration_id: str
    target_registration_version: int
    target_public_key_fingerprint: str
    target_public_key: bytes
    source_encrypted_dek: bytes
    source_context: bytes
    target_context: bytes
    schema_version: int = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise KeyCustodyError("custody_request_version_unsupported")
        for value in (
            self.backend,
            self.rotation_id,
            self.owner_aid,
            self.store_id,
            self.record_id,
            self.source_registration_id,
            self.source_public_key_fingerprint,
            self.target_registration_id,
            self.target_public_key_fingerprint,
        ):
            _text(value)
        _positive_int(self.expected_object_revision)
        _positive_int(self.source_registration_version)
        _positive_int(self.target_registration_version)
        for value in (
            self.source_public_key,
            self.target_public_key,
            self.source_encrypted_dek,
            self.source_context,
            self.target_context,
        ):
            if not isinstance(value, bytes) or not value:
                raise KeyCustodyError("custody_request_invalid")

    @property
    def request_digest(self) -> bytes:
        canonical = {
            "backend": self.backend,
            "expected_object_revision": self.expected_object_revision,
            "owner_aid": self.owner_aid,
            "record_id": self.record_id,
            "rotation_id": self.rotation_id,
            "schema_version": self.schema_version,
            "source_context_sha256": hashlib.sha256(self.source_context).hexdigest(),
            "source_encrypted_dek_sha256": hashlib.sha256(self.source_encrypted_dek).hexdigest(),
            "source_public_key": _b64(self.source_public_key),
            "source_public_key_fingerprint": self.source_public_key_fingerprint,
            "source_registration_id": self.source_registration_id,
            "source_registration_version": self.source_registration_version,
            "store_id": self.store_id,
            "target_context_sha256": hashlib.sha256(self.target_context).hexdigest(),
            "target_public_key": _b64(self.target_public_key),
            "target_public_key_fingerprint": self.target_public_key_fingerprint,
            "target_registration_id": self.target_registration_id,
            "target_registration_version": self.target_registration_version,
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(_REQUEST_DOMAIN + encoded).digest()

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "backend": self.backend,
            "rotation_id": self.rotation_id,
            "owner_aid": self.owner_aid,
            "store_id": self.store_id,
            "record_id": self.record_id,
            "expected_object_revision": self.expected_object_revision,
            "source_registration_id": self.source_registration_id,
            "source_registration_version": self.source_registration_version,
            "source_public_key_fingerprint": self.source_public_key_fingerprint,
            "source_public_key": _b64(self.source_public_key),
            "target_registration_id": self.target_registration_id,
            "target_registration_version": self.target_registration_version,
            "target_public_key_fingerprint": self.target_public_key_fingerprint,
            "target_public_key": _b64(self.target_public_key),
            "source_encrypted_dek": _b64(self.source_encrypted_dek),
            "source_context": _b64(self.source_context),
            "target_context": _b64(self.target_context),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "OwnerRewrapRequest":
        if not isinstance(payload, Mapping):
            raise KeyCustodyError("custody_payload_invalid")
        try:
            return cls(
                backend=payload["backend"],
                rotation_id=payload["rotation_id"],
                owner_aid=payload["owner_aid"],
                store_id=payload["store_id"],
                record_id=payload["record_id"],
                expected_object_revision=payload["expected_object_revision"],
                source_registration_id=payload["source_registration_id"],
                source_registration_version=payload["source_registration_version"],
                source_public_key_fingerprint=payload["source_public_key_fingerprint"],
                source_public_key=_unb64(payload["source_public_key"]),
                target_registration_id=payload["target_registration_id"],
                target_registration_version=payload["target_registration_version"],
                target_public_key_fingerprint=payload["target_public_key_fingerprint"],
                target_public_key=_unb64(payload["target_public_key"]),
                source_encrypted_dek=_unb64(payload["source_encrypted_dek"]),
                source_context=_unb64(payload["source_context"]),
                target_context=_unb64(payload["target_context"]),
                schema_version=payload["schema_version"],
            )
        except KeyCustodyError:
            raise
        except Exception as exc:
            raise KeyCustodyError("custody_payload_invalid") from exc


@dataclass(frozen=True, slots=True)
class OwnerRewrapApproval:
    """Owner-controlled approval for one exact Provider-exported request.

    Creating this object is the policy/intent decision. A custodian must obtain
    it independently of the Provider request transport before rewrapping.
    """

    request_digest: bytes
    owner_aid: str
    rotation_id: str
    store_id: str
    record_id: str
    expected_object_revision: int
    source_registration_id: str
    source_registration_version: int
    target_registration_id: str
    target_registration_version: int
    target_public_key_fingerprint: str
    target_public_key: bytes
    schema_version: int = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise KeyCustodyError("custody_approval_version_unsupported")
        if not isinstance(self.request_digest, bytes) or len(self.request_digest) != 32:
            raise KeyCustodyError("custody_approval_invalid")
        for value in (
            self.owner_aid,
            self.rotation_id,
            self.store_id,
            self.record_id,
            self.source_registration_id,
            self.target_registration_id,
            self.target_public_key_fingerprint,
        ):
            _text(value)
        _positive_int(self.expected_object_revision)
        _positive_int(self.source_registration_version)
        _positive_int(self.target_registration_version)
        if not isinstance(self.target_public_key, bytes) or not self.target_public_key:
            raise KeyCustodyError("custody_approval_invalid")

    def verify(self, request: OwnerRewrapRequest) -> None:
        if (
            self.schema_version != request.schema_version
            or not hmac.compare_digest(self.request_digest, request.request_digest)
            or self.owner_aid != request.owner_aid
            or self.rotation_id != request.rotation_id
            or self.store_id != request.store_id
            or self.record_id != request.record_id
            or self.expected_object_revision != request.expected_object_revision
            or self.source_registration_id != request.source_registration_id
            or self.source_registration_version != request.source_registration_version
            or self.target_registration_id != request.target_registration_id
            or self.target_registration_version != request.target_registration_version
            or self.target_public_key_fingerprint
            != request.target_public_key_fingerprint
            or not hmac.compare_digest(self.target_public_key, request.target_public_key)
        ):
            raise KeyCustodyError("custody_request_not_approved")

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_digest": _b64(self.request_digest),
            "owner_aid": self.owner_aid,
            "rotation_id": self.rotation_id,
            "store_id": self.store_id,
            "record_id": self.record_id,
            "expected_object_revision": self.expected_object_revision,
            "source_registration_id": self.source_registration_id,
            "source_registration_version": self.source_registration_version,
            "target_registration_id": self.target_registration_id,
            "target_registration_version": self.target_registration_version,
            "target_public_key_fingerprint": self.target_public_key_fingerprint,
            "target_public_key": _b64(self.target_public_key),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "OwnerRewrapApproval":
        if not isinstance(payload, Mapping):
            raise KeyCustodyError("custody_approval_invalid")
        try:
            return cls(
                request_digest=_unb64(payload["request_digest"]),
                owner_aid=payload["owner_aid"],
                rotation_id=payload["rotation_id"],
                store_id=payload["store_id"],
                record_id=payload["record_id"],
                expected_object_revision=payload["expected_object_revision"],
                source_registration_id=payload["source_registration_id"],
                source_registration_version=payload["source_registration_version"],
                target_registration_id=payload["target_registration_id"],
                target_registration_version=payload["target_registration_version"],
                target_public_key_fingerprint=payload["target_public_key_fingerprint"],
                target_public_key=_unb64(payload["target_public_key"]),
                schema_version=payload["schema_version"],
            )
        except KeyCustodyError:
            raise
        except Exception as exc:
            raise KeyCustodyError("custody_approval_invalid") from exc


@dataclass(frozen=True, slots=True)
class OwnerRewrapArtifact:
    request_digest: bytes
    target_encrypted_dek: bytes
    signature: bytes
    custody_key_id: str
    custody_algorithm: str
    custody_version: int
    schema_version: int = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise KeyCustodyError("custody_artifact_version_unsupported")
        if self.custody_version != _CUSTODY_VERSION:
            raise KeyCustodyError("custody_algorithm_version_unsupported")
        if self.custody_algorithm != _CUSTODY_ALGORITHM:
            raise KeyCustodyError("custody_algorithm_unsupported")
        if not isinstance(self.request_digest, bytes) or len(self.request_digest) != 32:
            raise KeyCustodyError("custody_artifact_invalid")
        if not isinstance(self.target_encrypted_dek, bytes) or not self.target_encrypted_dek:
            raise KeyCustodyError("custody_artifact_invalid")
        if not isinstance(self.signature, bytes) or not self.signature:
            raise KeyCustodyError("custody_artifact_invalid")
        _text(self.custody_key_id)

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_digest": _b64(self.request_digest),
            "target_encrypted_dek": _b64(self.target_encrypted_dek),
            "signature": _b64(self.signature),
            "custody_key_id": self.custody_key_id,
            "custody_algorithm": self.custody_algorithm,
            "custody_version": self.custody_version,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "OwnerRewrapArtifact":
        if not isinstance(payload, Mapping):
            raise KeyCustodyError("custody_payload_invalid")
        try:
            return cls(
                request_digest=_unb64(payload["request_digest"]),
                target_encrypted_dek=_unb64(payload["target_encrypted_dek"]),
                signature=_unb64(payload["signature"]),
                custody_key_id=payload["custody_key_id"],
                custody_algorithm=payload["custody_algorithm"],
                custody_version=payload["custody_version"],
                schema_version=payload["schema_version"],
            )
        except KeyCustodyError:
            raise
        except Exception as exc:
            raise KeyCustodyError("custody_payload_invalid") from exc


def _attestation_message(request_digest: bytes, target_encrypted_dek: bytes) -> bytes:
    return _ATTESTATION_DOMAIN + request_digest + hashlib.sha256(target_encrypted_dek).digest()


class UmbralOwnerKeyCustody:
    """Owner/KMS-side decrypt-and-fresh-encrypt plus source-key attestation."""

    def __init__(self, backend: UmbralPREBackend | None = None) -> None:
        self.backend = backend or UmbralPREBackend()

    def rewrap(
        self,
        request: OwnerRewrapRequest,
        source_private_key: bytes,
        approval: OwnerRewrapApproval,
    ) -> OwnerRewrapArtifact:
        if request.backend != self.backend.name:
            raise KeyCustodyError("custody_backend_mismatch")
        approval.verify(request)
        try:
            derived_source_key = self.backend.public_key_from_private(source_private_key)
            if not hmac.compare_digest(derived_source_key, request.source_public_key):
                raise KeyCustodyError("custody_source_key_mismatch")
            self.backend.validate_owner_wrapper(
                request.source_encrypted_dek,
                request.source_public_key,
                request.source_context,
            )
            target = self.backend.rewrap_dek(
                request.source_encrypted_dek,
                source_private_key,
                request.target_public_key,
                request.source_context,
                request.target_context,
            )
            self.backend.validate_owner_wrapper(target, request.target_public_key, request.target_context)
            signer = Signer(SecretKey.from_be_bytes(source_private_key))
            signature = signer.sign(_attestation_message(request.request_digest, target)).to_der_bytes()
        except KeyCustodyError:
            raise
        except PREBackendError as exc:
            raise KeyCustodyError("custody_request_invalid") from exc
        except Exception as exc:
            raise KeyCustodyError("custody_operation_failed") from exc
        return OwnerRewrapArtifact(
            request_digest=request.request_digest,
            target_encrypted_dek=target,
            signature=signature,
            custody_key_id=request.source_registration_id,
            custody_algorithm=_CUSTODY_ALGORITHM,
            custody_version=_CUSTODY_VERSION,
        )


def verify_custody_artifact(
    request: OwnerRewrapRequest,
    artifact: OwnerRewrapArtifact,
    *,
    backend: UmbralPREBackend | None = None,
) -> None:
    """Verify an owner artifact using only the request's source public key."""
    concrete = backend or UmbralPREBackend()
    if request.backend != concrete.name:
        raise KeyCustodyError("custody_backend_mismatch")
    if not hmac.compare_digest(artifact.request_digest, request.request_digest):
        raise KeyCustodyError("custody_request_digest_mismatch")
    if artifact.custody_key_id != request.source_registration_id:
        raise KeyCustodyError("custody_signature_invalid")
    try:
        concrete.validate_owner_wrapper(
            artifact.target_encrypted_dek,
            request.target_public_key,
            request.target_context,
        )
    except PREBackendError as exc:
        raise KeyCustodyError("custody_target_wrapper_invalid") from exc
    try:
        signature = Signature.from_der_bytes(artifact.signature)
        source_key = PublicKey.from_compressed_bytes(request.source_public_key)
        if not signature.verify(
            source_key,
            _attestation_message(request.request_digest, artifact.target_encrypted_dek),
        ):
            raise KeyCustodyError("custody_signature_invalid")
    except KeyCustodyError:
        raise
    except Exception as exc:
        raise KeyCustodyError("custody_signature_invalid") from exc

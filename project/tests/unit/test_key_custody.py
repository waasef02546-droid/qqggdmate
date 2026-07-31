from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from presaga.crypto.key_custody import (
    KeyCustodyError,
    OwnerRewrapApproval,
    OwnerRewrapArtifact,
    OwnerRewrapRequest,
    UmbralOwnerKeyCustody,
    verify_custody_artifact,
)
from presaga.crypto.umbral_pre import UmbralPREBackend, UmbralFormatError, UmbralValidationError
from scripts.create_owner_rewrap_artifact import create_artifact


class KeyCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = UmbralPREBackend()
        self.source = self.backend.generate_keypair()
        self.target = self.backend.generate_keypair()
        self.dek = b"d" * 32
        self.source_context = hashlib.sha256(b"source-context").digest()
        self.target_context = hashlib.sha256(b"target-context").digest()
        self.source_wrapper = self.backend.wrap_dek(
            self.dek, self.source.public_key, self.source_context
        )
        self.request = OwnerRewrapRequest(
            backend=self.backend.name,
            rotation_id="rotation-1",
            owner_aid="did:example:owner",
            store_id="store-1",
            record_id="record-1",
            expected_object_revision=7,
            source_registration_id="registration-1",
            source_registration_version=1,
            source_public_key_fingerprint="a" * 64,
            source_public_key=self.source.public_key,
            target_registration_id="registration-2",
            target_registration_version=2,
            target_public_key_fingerprint="b" * 64,
            target_public_key=self.target.public_key,
            source_encrypted_dek=self.source_wrapper,
            source_context=self.source_context,
            target_context=self.target_context,
        )
        self.custody = UmbralOwnerKeyCustody(self.backend)
        self.approval = OwnerRewrapApproval(
            request_digest=self.request.request_digest,
            owner_aid=self.request.owner_aid,
            rotation_id=self.request.rotation_id,
            store_id=self.request.store_id,
            record_id=self.request.record_id,
            expected_object_revision=self.request.expected_object_revision,
            source_registration_id=self.request.source_registration_id,
            source_registration_version=self.request.source_registration_version,
            target_registration_id=self.request.target_registration_id,
            target_registration_version=self.request.target_registration_version,
            target_public_key_fingerprint=self.request.target_public_key_fingerprint,
            target_public_key=self.request.target_public_key,
        )

    def test_rewrap_and_public_verification_succeed(self) -> None:
        artifact = self.custody.rewrap(
            self.request,
            self.source.private_key,
            self.approval,
        )

        self.assertIsNone(verify_custody_artifact(self.request, artifact, backend=self.backend))
        self.assertEqual(
            self.dek,
            self.backend.unwrap_dek(
                artifact.target_encrypted_dek,
                self.target.private_key,
                self.target_context,
            ),
        )
        self.assertNotIn(self.source.private_key, artifact.target_encrypted_dek)
        self.assertEqual(self.request, OwnerRewrapRequest.from_payload(self.request.to_payload()))
        self.assertEqual(
            self.approval,
            OwnerRewrapApproval.from_payload(self.approval.to_payload()),
        )
        self.assertEqual(artifact, OwnerRewrapArtifact.from_payload(artifact.to_payload()))

    def test_wrong_source_private_key_is_denied(self) -> None:
        wrong = self.backend.generate_keypair()
        with self.assertRaisesRegex(KeyCustodyError, "custody_source_key_mismatch"):
            self.custody.rewrap(self.request, wrong.private_key, self.approval)

    def test_owner_approval_rejects_provider_target_or_scope_substitution(self) -> None:
        attacker_target = self.backend.generate_keypair()
        cases = (
            replace(self.request, record_id="attacker-record"),
            replace(
                self.request,
                target_registration_id="attacker-registration",
                target_public_key_fingerprint="e" * 64,
                target_public_key=attacker_target.public_key,
            ),
        )
        for candidate in cases:
            with self.subTest(record_id=candidate.record_id):
                with self.assertRaisesRegex(
                    KeyCustodyError,
                    "custody_request_not_approved",
                ):
                    self.custody.rewrap(
                        candidate,
                        self.source.private_key,
                        self.approval,
                    )

    def test_signature_target_and_digest_tamper_are_denied(self) -> None:
        artifact = self.custody.rewrap(
            self.request,
            self.source.private_key,
            self.approval,
        )
        valid_but_unsigned_target = self.backend.wrap_dek(
            b"e" * 32, self.target.public_key, self.target_context
        )
        cases = (
            (
                replace(artifact, signature=artifact.signature[:-1] + bytes([artifact.signature[-1] ^ 1])),
                "custody_signature_invalid",
            ),
            (
                replace(artifact, target_encrypted_dek=artifact.target_encrypted_dek[:-1] + b"x"),
                "custody_target_wrapper_invalid",
            ),
            (
                replace(artifact, target_encrypted_dek=valid_but_unsigned_target),
                "custody_signature_invalid",
            ),
            (
                replace(artifact, request_digest=b"x" * 32),
                "custody_request_digest_mismatch",
            ),
        )
        for candidate, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(KeyCustodyError, reason):
                    verify_custody_artifact(self.request, candidate, backend=self.backend)

    def test_cross_request_artifact_is_denied(self) -> None:
        artifact = self.custody.rewrap(
            self.request,
            self.source.private_key,
            self.approval,
        )
        other = replace(self.request, record_id="record-2")
        with self.assertRaisesRegex(KeyCustodyError, "custody_request_digest_mismatch"):
            verify_custody_artifact(other, artifact, backend=self.backend)

    def test_request_digest_binds_every_rotation_and_object_input(self) -> None:
        mutations = {
            "backend": "other",
            "rotation_id": "rotation-2",
            "owner_aid": "did:example:other",
            "store_id": "store-2",
            "record_id": "record-2",
            "expected_object_revision": 8,
            "source_registration_id": "registration-x",
            "source_registration_version": 2,
            "source_public_key_fingerprint": "c" * 64,
            "source_public_key": self.backend.generate_keypair().public_key,
            "target_registration_id": "registration-y",
            "target_registration_version": 3,
            "target_public_key_fingerprint": "d" * 64,
            "target_public_key": self.backend.generate_keypair().public_key,
            "source_encrypted_dek": self.source_wrapper + b"x",
            "source_context": self.source_context + b"x",
            "target_context": self.target_context + b"x",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    self.request.request_digest,
                    replace(self.request, **{field: value}).request_digest,
                )

    def test_public_wrapper_validation_checks_format_key_and_context(self) -> None:
        self.assertIsNone(
            self.backend.validate_owner_wrapper(
                self.source_wrapper, self.source.public_key, self.source_context
            )
        )
        with self.assertRaises(UmbralValidationError):
            self.backend.validate_owner_wrapper(
                self.source_wrapper, self.target.public_key, self.source_context
            )
        with self.assertRaises(UmbralValidationError):
            self.backend.validate_owner_wrapper(
                self.source_wrapper, self.source.public_key, b"wrong-context"
            )
        with self.assertRaises(UmbralFormatError):
            self.backend.validate_owner_wrapper(
                self.source_wrapper[:-1], self.source.public_key, self.source_context
            )

    def test_owner_side_file_tool_never_emits_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            approval_path = root / "approval.json"
            private_key_path = root / "owner-key.b64"
            request_path.write_text(
                json.dumps({"request": self.request.to_payload()}),
                encoding="utf-8",
            )
            approval_path.write_text(
                json.dumps({"approval": self.approval.to_payload()}),
                encoding="utf-8",
            )
            private_key_path.write_text(
                base64.b64encode(self.source.private_key).decode("ascii"),
                encoding="ascii",
            )

            payload = create_artifact(
                request_path,
                approval_path,
                private_key_path,
            )

            artifact = OwnerRewrapArtifact.from_payload(payload)
            self.assertIsNone(
                verify_custody_artifact(self.request, artifact, backend=self.backend)
            )
            self.assertNotIn(
                base64.b64encode(self.source.private_key).decode("ascii"),
                json.dumps(payload, sort_keys=True),
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import unittest

from presaga.crypto.pre_interface import PREBackendError
from presaga.crypto.umbral_pre import (
    UmbralFormatError,
    UmbralPREBackend,
    UmbralValidationError,
)


class UmbralPREBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = UmbralPREBackend()
        self.owner = self.backend.generate_keypair()
        self.requester = self.backend.generate_keypair()
        self.context = b"record/7|epoch/3|policy/fingerprint"
        self.dek = os.urandom(32)
        self.owner_wrapper = self.backend.wrap_dek(
            self.dek,
            self.owner.public_key,
            self.context,
        )
        self.rekey = self.backend.generate_rekey(
            self.owner.private_key,
            self.requester.public_key,
            self.context,
        )

    def transform(self) -> bytes:
        return self.backend.transform(
            self.owner_wrapper,
            self.rekey,
            context=self.context,
            owner_public_key=self.owner.public_key,
            requester_public_key=self.requester.public_key,
        )

    def test_owner_and_requester_round_trip(self) -> None:
        self.assertEqual(
            self.backend.unwrap_dek(
                self.owner_wrapper,
                self.owner.private_key,
                self.context,
            ),
            self.dek,
        )
        self.assertEqual(
            self.backend.unwrap_dek(
                self.transform(),
                self.requester.private_key,
                self.context,
            ),
            self.dek,
        )

    def test_public_material_cannot_recover_dek(self) -> None:
        public_material = self.owner_wrapper + self.rekey
        self.assertNotIn(self.dek, public_material)
        with self.assertRaises(PREBackendError):
            self.backend.unwrap_dek(
                self.owner_wrapper,
                self.owner.public_key,
                self.context,
            )

    def test_transform_requires_server_binding_inputs(self) -> None:
        with self.assertRaisesRegex(
            UmbralValidationError,
            "transform_context_required",
        ):
            self.backend.transform(
                self.owner_wrapper,
                self.rekey,
                owner_public_key=self.owner.public_key,
                requester_public_key=self.requester.public_key,
            )
        with self.assertRaisesRegex(
            UmbralValidationError,
            "transform_owner_key_required",
        ):
            self.backend.transform(
                self.owner_wrapper,
                self.rekey,
                context=self.context,
                requester_public_key=self.requester.public_key,
            )
        with self.assertRaisesRegex(
            UmbralValidationError,
            "transform_requester_key_required",
        ):
            self.backend.transform(
                self.owner_wrapper,
                self.rekey,
                context=self.context,
                owner_public_key=self.owner.public_key,
            )

    def test_transform_rejects_context_owner_and_requester_mismatches(self) -> None:
        other_owner = self.backend.generate_keypair()
        other_requester = self.backend.generate_keypair()
        wrong_owner_rekey = self.backend.generate_rekey(
            other_owner.private_key,
            self.requester.public_key,
            self.context,
        )
        for rekey, context, owner, requester, message in (
            (
                self.rekey,
                b"other-context",
                self.owner.public_key,
                self.requester.public_key,
                "context_mismatch",
            ),
            (
                self.rekey,
                self.context,
                other_owner.public_key,
                self.requester.public_key,
                "owner_registration_key_mismatch",
            ),
            (
                wrong_owner_rekey,
                self.context,
                self.owner.public_key,
                self.requester.public_key,
                "rekey_owner_key_mismatch",
            ),
            (
                self.rekey,
                self.context,
                self.owner.public_key,
                other_requester.public_key,
                "rekey_requester_key_mismatch",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(UmbralValidationError, message):
                    self.backend.transform(
                        self.owner_wrapper,
                        rekey,
                        context=context,
                        owner_public_key=owner,
                        requester_public_key=requester,
                    )

    def test_wrong_private_keys_and_context_are_rejected(self) -> None:
        transformed = self.transform()
        for wrapper, private_key, context, message in (
            (
                self.owner_wrapper,
                self.requester.private_key,
                self.context,
                "owner_private_key_mismatch",
            ),
            (
                transformed,
                self.owner.private_key,
                self.context,
                "requester_private_key_mismatch",
            ),
            (
                transformed,
                self.requester.private_key,
                b"other-context",
                "context_mismatch",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(PREBackendError, message):
                    self.backend.unwrap_dek(wrapper, private_key, context)

    def test_envelopes_and_fragments_reject_tampering(self) -> None:
        transformed = self.transform()
        mutations = {
            "owner_header": self.owner_wrapper[:4] + b"\x00" + self.owner_wrapper[5:],
            "owner_payload": self.owner_wrapper[:-1]
            + bytes([self.owner_wrapper[-1] ^ 1]),
            "rekey_payload": self.rekey[:-1] + bytes([self.rekey[-1] ^ 1]),
            "transformed_payload": transformed[:-1]
            + bytes([transformed[-1] ^ 1]),
        }
        with self.assertRaises(PREBackendError):
            self.backend.unwrap_dek(
                mutations["owner_header"],
                self.owner.private_key,
                self.context,
            )
        with self.assertRaises(PREBackendError):
            self.backend.unwrap_dek(
                mutations["owner_payload"],
                self.owner.private_key,
                self.context,
            )
        with self.assertRaises(PREBackendError):
            self.backend.transform(
                self.owner_wrapper,
                mutations["rekey_payload"],
                context=self.context,
                owner_public_key=self.owner.public_key,
                requester_public_key=self.requester.public_key,
            )
        with self.assertRaises(PREBackendError):
            self.backend.unwrap_dek(
                mutations["transformed_payload"],
                self.requester.private_key,
                self.context,
            )

    def test_malformed_envelopes_raise_stable_backend_errors(self) -> None:
        malformed = (
            b"",
            b"short",
            self.owner_wrapper + b"trailing",
            self.owner_wrapper[:6] + b"\xff" + self.owner_wrapper[7:],
        )
        for value in malformed:
            with self.subTest(value=value[:12]):
                with self.assertRaises(PREBackendError):
                    self.backend.unwrap_dek(
                        value,
                        self.owner.private_key,
                        self.context,
                    )

    def test_trusted_management_rewrap_creates_fresh_target_wrapper(self) -> None:
        target = self.backend.generate_keypair()
        target_context = b"record/7|epoch/4|policy/new"
        rotated = self.backend.rewrap_dek(
            self.owner_wrapper,
            self.owner.private_key,
            target.public_key,
            self.context,
            target_context,
        )
        self.assertNotEqual(rotated, self.owner_wrapper)
        self.assertEqual(
            self.backend.unwrap_dek(
                rotated,
                target.private_key,
                target_context,
            ),
            self.dek,
        )

    def test_dek_size_is_explicit(self) -> None:
        with self.assertRaisesRegex(
            UmbralValidationError,
            "dek_must_be_32_bytes",
        ):
            self.backend.wrap_dek(
                b"not-a-32-byte-dek",
                self.owner.public_key,
                self.context,
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from presaga.crypto import envelope
from presaga.crypto.toy_pre import ToyPRE


class EnvelopeEncryptionTest(unittest.TestCase):
    def test_toy_pre_public_material_recovery_remains_a_defect_fixture(self):
        """Keep the historical ToyPRE compromise reproducible and labelled."""
        backend = ToyPRE()
        owner = backend.generate_keypair()
        context = b"toy-defect-characterization"
        dek = envelope.generate_dek()
        owner_wrapped = backend.wrap_dek(dek, owner.public_key, context)

        recovered = backend.wrap_dek(
            owner_wrapped,
            owner.public_key,
            context,
        )
        self.assertEqual(dek, recovered)

    def test_round_trip_and_portable_format(self):
        dek = envelope.generate_dek()
        sealed = envelope.encrypt(b"calendar availability", dek, b"alice|cal-1|v1")

        # JSON round-trip models a process/persistence boundary.
        portable = json.loads(json.dumps(sealed.to_dict()))
        restored = envelope.EnvelopeCiphertext.from_dict(portable)

        self.assertEqual(restored.algorithm, envelope.ENVELOPE_ALGORITHM)
        self.assertEqual(restored.version, envelope.ENVELOPE_VERSION)
        self.assertEqual(envelope.decrypt(restored, dek, b"alice|cal-1|v1"), b"calendar availability")

    def test_aad_mismatch_and_aad_tampering_are_rejected(self):
        dek = envelope.generate_dek()
        sealed = envelope.encrypt(b"private", dek, b"record-a")

        with self.assertRaises(envelope.EnvelopeAuthenticationError):
            envelope.decrypt(sealed, dek, b"record-b")
        with self.assertRaises(envelope.EnvelopeAuthenticationError):
            envelope.decrypt(replace(sealed, aad=b"record-b"), dek)

    def test_ciphertext_tag_and_nonce_tampering_are_rejected(self):
        dek = envelope.generate_dek()
        sealed = envelope.encrypt(b"private", dek, b"record-a")
        tampered_ciphertext = replace(sealed, ciphertext=bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:])
        tampered_tag = replace(sealed, tag=bytes([sealed.tag[0] ^ 1]) + sealed.tag[1:])
        tampered_nonce = replace(sealed, nonce=bytes([sealed.nonce[0] ^ 1]) + sealed.nonce[1:])

        for candidate in (tampered_ciphertext, tampered_tag, tampered_nonce):
            with self.assertRaises(envelope.EnvelopeAuthenticationError):
                envelope.decrypt(candidate, dek)

    def test_nonce_size_and_freshness(self):
        dek = envelope.generate_dek()
        nonces = {envelope.encrypt(b"same payload", dek, b"record-a").nonce for _ in range(128)}

        self.assertEqual(len(nonces), 128)
        self.assertTrue(all(len(nonce) == envelope.NONCE_SIZE for nonce in nonces))

    def test_unsupported_format_is_rejected(self):
        sealed = envelope.encrypt(b"private", envelope.generate_dek(), b"record-a")
        invalid = sealed.to_dict()
        invalid["algorithm"] = "legacy-stream-cipher"

        with self.assertRaises(envelope.EnvelopeAuthenticationError):
            envelope.EnvelopeCiphertext.from_dict(invalid)

    def test_replayed_rekey_in_another_context_cannot_decrypt_aead_payload(self):
        """A toy-PRE replay across record contexts produces no usable DEK.

        This is not a PRE security proof; it verifies the key-transform context
        and AEAD authenticity combine to reject a cross-record replay.
        """
        backend = ToyPRE()
        owner = backend.generate_keypair()
        requester = backend.generate_keypair()
        context_one = b"alice|calendar-1|calendar|v1"
        context_two = b"alice|calendar-2|calendar|v1"
        dek = envelope.generate_dek()
        sealed = envelope.encrypt(b"private", dek, context_one)
        owner_wrapped = backend.wrap_dek(dek, owner.public_key, context_one)
        replayed_rekey = backend.generate_rekey(owner.private_key, requester.public_key, context_one)
        transformed = backend.transform(owner_wrapped, replayed_rekey)

        replayed_dek = backend.unwrap_dek(transformed, requester.private_key, context_two)
        with self.assertRaises(envelope.EnvelopeAuthenticationError):
            envelope.decrypt(sealed, replayed_dek, context_two)


if __name__ == "__main__":
    unittest.main()

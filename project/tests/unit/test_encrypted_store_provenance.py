from __future__ import annotations

import inspect
import unittest
from dataclasses import replace

from presaga.crypto import envelope
from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import DataRecord
from presaga.provider.registry import AgentRegistry, RegistrationError
from presaga.storage.encrypted_store import EncryptedStore, StorageProvenanceError


class EncryptedStoreProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = ToyPRE()
        self.owner = self.backend.generate_keypair()
        self.registry = AgentRegistry()
        self.registration = self.registry.create(
            "alice@example.com:calendar",
            self.owner.public_key,
            actor="manager",
        )
        self.store = EncryptedStore(self.backend, self.registry)
        self.record = DataRecord(
            "cal-provenance-1",
            self.registration.aid,
            "calendar",
            "availability",
            1,
        )

    def test_put_uses_authoritative_registration_and_has_no_raw_key_parameter(self) -> None:
        self.assertNotIn("owner_public_key", inspect.signature(self.store.put).parameters)
        stored = self.store.put(self.record, b"available")
        wrapped = self.store.resolve_active_owner_wrap(stored)

        self.assertEqual(self.registration.aid, wrapped.provenance.owner_aid)
        self.assertEqual(self.registration.registration_id, wrapped.provenance.registration_id)
        self.assertEqual(
            self.registration.registration_version,
            wrapped.provenance.registration_version,
        )
        self.assertEqual(
            self.registration.public_key_fingerprint,
            wrapped.provenance.public_key_fingerprint,
        )
        self.assertEqual(self.registration.key_algorithm, wrapped.provenance.key_algorithm)
        dek = self.backend.unwrap_dek(
            wrapped.encrypted_dek,
            self.owner.private_key,
            self.store.context(self.record),
        )
        self.assertEqual(b"available", self.store.decrypt_with_dek(stored, dek))
        with self.assertRaises(TypeError):
            self.store.put(replace(self.record, record_id="raw-key"), b"x", self.owner.public_key)

    def test_unknown_revoked_and_legacy_owner_fail_closed(self) -> None:
        unknown = replace(self.record, record_id="unknown", owner_aid="unknown@example.com:agent")
        with self.assertRaisesRegex(RegistrationError, "registration_not_found"):
            self.store.put(unknown, b"x")

        revoked_pair = self.backend.generate_keypair()
        revoked = self.registry.create(
            "revoked@example.com:agent", revoked_pair.public_key, actor="manager"
        )
        self.registry.revoke(revoked.aid, actor="manager", expected_version=1)
        with self.assertRaisesRegex(RegistrationError, "registration_not_active"):
            self.store.put(
                replace(self.record, record_id="revoked", owner_aid=revoked.aid),
                b"x",
            )

        legacy_pair = self.backend.generate_keypair()
        legacy = self.registry.import_legacy("legacy@example.com:agent", legacy_pair.public_key)
        with self.assertRaisesRegex(RegistrationError, "registration_not_active"):
            self.store.put(
                replace(self.record, record_id="legacy", owner_aid=legacy.aid),
                b"x",
            )

    def test_provenance_tamper_and_record_aad_tamper_fail_closed(self) -> None:
        stored = self.store.put(self.record, b"available")
        wrapped = stored.owner_wraps[0]
        bad_provenance = replace(
            wrapped.provenance,
            public_key_fingerprint="0" * 64,
        )
        tampered_wrap = replace(
            stored,
            owner_wraps=(replace(wrapped, provenance=bad_provenance),),
        )
        with self.assertRaisesRegex(StorageProvenanceError, "owner_wrap_not_found"):
            self.store.resolve_active_owner_wrap(tampered_wrap)

        dek = self.backend.unwrap_dek(
            wrapped.encrypted_dek,
            self.owner.private_key,
            self.store.context(self.record),
        )
        tampered_record = replace(
            stored,
            record=replace(self.record, data_class="mail"),
        )
        with self.assertRaises(envelope.EnvelopeAuthenticationError):
            self.store.decrypt_with_dek(tampered_record, dek)


if __name__ == "__main__":
    unittest.main()

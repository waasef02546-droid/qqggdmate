from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from presaga.provider.registry import AgentRegistry, RegistrationError, key_fingerprint


class AgentRegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AgentRegistry()
        self.aid = "bob@example.com:scheduler"
        self.key_v1 = b"k" * 32
        self.key_v2 = b"n" * 32

    def test_create_derives_versioned_domain_separated_fingerprint(self) -> None:
        record = self.registry.create(self.aid, self.key_v1, actor="manager-a")

        self.assertEqual(1, record.registration_version)
        self.assertEqual("active", record.status)
        self.assertEqual("manager-a", record.registered_by)
        self.assertEqual(key_fingerprint(self.key_v1), record.public_key_fingerprint)
        self.assertNotEqual(record.public_key_fingerprint, __import__("hashlib").sha256(self.key_v1).hexdigest())
        self.assertEqual(record, self.registry.resolve_active(self.aid))

    def test_duplicate_unknown_and_malformed_records_fail_closed(self) -> None:
        self.registry.create(self.aid, self.key_v1, actor="manager-a")

        cases = (
            (lambda: self.registry.create(self.aid, self.key_v1, actor="manager-a"), "registration_exists"),
            (lambda: self.registry.resolve_active("missing@example.com:agent"), "registration_not_found"),
            (lambda: self.registry.create(" bad aid ", self.key_v1, actor="manager-a"), "aid_invalid"),
            (lambda: self.registry.create("short@example.com:a", b"tiny", actor="manager-a"), "public_key_invalid"),
        )
        for operation, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(RegistrationError, reason):
                operation()

    def test_replace_requires_original_actor_and_exact_current_version(self) -> None:
        self.registry.create(self.aid, self.key_v1, actor="manager-a")

        with self.assertRaisesRegex(RegistrationError, "registration_actor_forbidden"):
            self.registry.replace(
                self.aid,
                self.key_v2,
                actor="manager-b",
                expected_version=1,
            )
        with self.assertRaisesRegex(RegistrationError, "registration_version_conflict"):
            self.registry.replace(
                self.aid,
                self.key_v2,
                actor="manager-a",
                expected_version=0,
            )

        updated = self.registry.replace(
            self.aid,
            self.key_v2,
            actor="manager-a",
            expected_version=1,
        )
        self.assertEqual(2, updated.registration_version)
        self.assertEqual(key_fingerprint(self.key_v2), updated.public_key_fingerprint)

    def test_concurrent_replacement_has_exactly_one_cas_winner(self) -> None:
        self.registry.create(self.aid, self.key_v1, actor="manager-a")

        def replace_key(index: int) -> str:
            try:
                self.registry.replace(
                    self.aid,
                    bytes([index + 1]) * 32,
                    actor="manager-a",
                    expected_version=1,
                )
                return "updated"
            except RegistrationError as error:
                return error.reason

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(replace_key, range(8)))

        self.assertEqual(1, results.count("updated"))
        self.assertEqual(7, results.count("registration_version_conflict"))
        self.assertEqual(2, self.registry.resolve_active(self.aid).registration_version)

    def test_revocation_is_a_versioned_tombstone(self) -> None:
        self.registry.create(self.aid, self.key_v1, actor="manager-a")
        revoked = self.registry.revoke(self.aid, actor="manager-a", expected_version=1)

        self.assertEqual("revoked", revoked.status)
        self.assertEqual(2, revoked.registration_version)
        with self.assertRaisesRegex(RegistrationError, "registration_not_active"):
            self.registry.resolve_active(self.aid)
        with self.assertRaisesRegex(RegistrationError, "registration_exists"):
            self.registry.create(self.aid, self.key_v2, actor="manager-a")

    def test_restore_rejects_corrupt_fingerprint_and_legacy_is_quarantined(self) -> None:
        record = self.registry.create(self.aid, self.key_v1, actor="manager-a")
        restored = AgentRegistry()
        with self.assertRaisesRegex(RegistrationError, "registration_fingerprint_invalid"):
            restored.restore(replace(record, public_key_fingerprint="0" * 64))

        legacy = restored.import_legacy("legacy@example.com:agent", b"l" * 32)
        self.assertEqual("legacy_unverified", legacy.status)
        with self.assertRaisesRegex(RegistrationError, "registration_not_active"):
            restored.resolve_active(legacy.aid)


if __name__ == "__main__":
    unittest.main()

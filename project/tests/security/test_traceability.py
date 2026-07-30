"""Structural guard for the paper-to-prototype traceability matrix.

This test deliberately verifies stable evidence references rather than making a
cryptographic claim.  Semantic properties continue to live in the targeted unit,
integration, attack, and optional ProVerif runs referenced by the matrix.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "traceability_matrix.md"


class TraceabilityMatrixTest(unittest.TestCase):
    def test_authoritative_paths_select_the_pinned_umbral_backend(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"nucypher-core==0.15.0"', pyproject)

        paths = (
            ROOT / "presaga" / "provider" / "server.py",
            ROOT / "experiments" / "attacks" / "common.py",
            ROOT / "experiments" / "tasks" / "common.py",
            ROOT / "experiments" / "e2e" / "saga_bridge.py",
            ROOT / "experiments" / "e2e" / "mongodb_e2e.py",
        )
        for path in paths:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertIn("UmbralPREBackend", content)
                self.assertNotIn("ToyPRE()", content)
                self.assertNotIn("HPKEKEMStub()", content)

    def test_matrix_covers_required_security_claims(self):
        content = MATRIX.read_text(encoding="utf-8")
        for claim in (
            "T1 data-token authenticity",
            "T2 DEK secrecy from the data-plane Provider",
            "T3 re-encryption authentication",
            "T4 policy denial after contact authorization",
            "T5 replay prevention",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, content)

    def test_matrix_references_exist(self):
        references = (
            "proofs/presaga_token_secrecy.pv",
            "proofs/presaga_dek_secrecy.pv",
            "proofs/presaga_rekey_authentication.pv",
            "presaga/protocol/schemas.py",
            "presaga/provider/token_service.py",
            "presaga/provider/pre_proxy.py",
            "presaga/provider/data_policy.py",
            "presaga/provider/audit.py",
            "tests/unit/test_token_service.py",
            "tests/unit/test_data_policy.py",
            "tests/unit/test_crypto_envelope.py",
            "tests/integration/test_normal_sharing.py",
            "tests/security/test_formal_artifacts.py",
            "tests/security/test_attack_scripts.py",
            "experiments/attacks/provider_plaintext_probe.py",
            "experiments/attacks/unauthorized_data_class.py",
            "experiments/attacks/purpose_mismatch.py",
            "experiments/attacks/requester_mismatch.py",
            "experiments/attacks/stale_rekey_use.py",
            "experiments/attacks/token_reuse.py",
        )
        for relative_path in references:
            with self.subTest(path=relative_path):
                self.assertTrue((ROOT / relative_path).is_file())

    def test_schema_retains_security_binding_and_audit_fields(self):
        schema = (ROOT / "presaga" / "protocol" / "schemas.py").read_text(encoding="utf-8")
        fields = (
            "class DataAccessRequest:",
            "requester_public_key: bytes",
            "class DataToken:",
            "allowed_record_ids: list[str]",
            "allowed_data_classes: list[str]",
            "purpose: str",
            "remaining_uses: int",
            "min_version: int",
            "max_version: int",
            "requester_public_key_hash: str",
            "issuer_signature: str",
            "class AuditEvent:",
            "provider_saw_plaintext_dek: bool",
            "provider_saw_plaintext_data: bool",
        )
        for field in fields:
            with self.subTest(field=field):
                self.assertIn(field, schema)

    def test_matrix_discloses_model_boundary(self):
        content = MATRIX.read_text(encoding="utf-8")
        normalized = " ".join(content.split())
        for boundary in (
            "not a proof that the selected concrete dependency or adapter is production-secure",
            "does not prevent a legitimate requester from leaking already decrypted plaintext",
            "distributed replay resistance",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, normalized)


if __name__ == "__main__":
    unittest.main()

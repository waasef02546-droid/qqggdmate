from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiments.release import _artifact_inventory
from experiments.release_verifier import (
    EXPECTED_ARTIFACTS,
    EXPECTED_GATES,
    MANIFEST_NAME,
    source_fingerprint,
    verify_release,
)


class ReleaseEvidenceTest(unittest.TestCase):
    def test_verifier_accepts_consistent_release_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_semantic_fixture(root)
            manifest = self._manifest(root)
            (root / MANIFEST_NAME).write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            accepted = verify_release(root)
            self.assertTrue(accepted.valid, accepted.errors)

            with (root / "tables" / "task_results.csv").open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write("tampered,False,corrupt,0\n")
            rejected = verify_release(root)
            self.assertFalse(rejected.valid)
            self.assertTrue(
                any("artifact_hash_mismatch" in error for error in rejected.errors)
            )

    def test_verifier_rejects_weakened_custody_semantics_with_valid_hashes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_semantic_fixture(root)
            custody_path = root / "tables" / "key_custody_summary.csv"
            with custody_path.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            row["exact_retry_idempotent"] = "False"
            self._write_csv(custody_path, [row])
            manifest = self._manifest(root)
            (root / MANIFEST_NAME).write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            rejected = verify_release(root)
            self.assertFalse(rejected.valid)
            self.assertIn(
                "key_custody_boundary_semantics_failed",
                rejected.errors,
            )
            self.assertFalse(
                any("artifact_hash_mismatch" in error for error in rejected.errors)
            )

    def _manifest(self, root: Path) -> dict:
        source_hash, source_count = source_fingerprint()
        return {
                "schema_version": 1,
                "status": "accepted",
                "source": {
                    "fingerprint_sha256": source_hash,
                    "file_count": source_count,
                },
                "git": {"release_inputs_dirty": False},
                "environment": {
                    "dependencies": {"nucypher-core": "0.15.0"},
                    "crypto_backend": {
                        "name": "umbral-pre-v1",
                        "dependency_distribution": "nucypher-core",
                        "dependency_version": "0.15.0",
                        "adapter_format_version": 1,
                        "threshold": 1,
                        "shares": 1,
                    },
                },
                "config": {
                    "values": {
                        "performance": {"policy_rule_counts": [10]},
                        "required": {
                            "blocking_attacks": 8,
                            "limitation_probes": 0,
                            "successful_tasks": 4,
                            "proverif_models": 3,
                            "saga_bridge_cases": 2,
                            "key_custody_cases": 1,
                            "mongodb_e2e": True,
                        },
                    }
                },
                "gates": [
                    {"name": name, "passed": True} for name in EXPECTED_GATES
                ],
                "artifacts": _artifact_inventory(root),
            }

    def _write_semantic_fixture(self, root: Path) -> None:
        tables = root / "tables"
        proofs = root / "proofs"
        tables.mkdir(parents=True)
        proofs.mkdir(parents=True)

        attacks = [
            {
                "attack": f"blocking-{index}",
                "expected_blocked": True,
                "blocked": True,
                "success": True,
                "reason": "blocked",
                "path_kind": "provider_service",
            }
            for index in range(7)
        ]
        attacks.append(
            {
                "attack": "provider_plaintext_probe",
                "expected_blocked": True,
                "blocked": True,
                "success": True,
                "reason": "provider_public_material_recovery_blocked",
                "path_kind": "provider_service",
            }
        )
        self._write_csv(tables / "security_matrix.csv", attacks)

        tasks = [
            {
                "task": f"task-{index}",
                "success": True,
                "latency_ms": float(index + 1),
            }
            for index in range(4)
        ]
        self._write_csv(tables / "task_results.csv", tasks)
        self._write_csv(
            tables / "task_latency_breakdown.csv",
            [
                {
                    "task": row["task"],
                    "total_latency_ms": row["latency_ms"],
                }
                for row in tasks
            ],
        )

        performance = []
        for baseline, path, confidentiality in (
            ("saga_contact_only", "modeled_contact_baseline", ""),
            ("presaga_policy_only", "policy_microbenchmark", ""),
            ("plaintext_token_server", "modeled_plaintext_baseline", False),
            ("presaga", "provider_service", True),
        ):
            performance.append(
                {
                    "baseline": baseline,
                    "path_kind": path,
                    "provider_recovery_gate_linked": confidentiality,
                }
            )
        self._write_csv(tables / "performance.csv", performance)

        self._write_csv(
            proofs / "proverif_summary.csv",
            [
                {
                    "proof": f"proof-{index}.pv",
                    "status": "passed",
                    "verified_queries": 1,
                }
                for index in range(3)
            ],
        )
        self._write_csv(
            tables / "saga_bridge_summary.csv",
            [
                {
                    "case": "alice_bob_authorized_calendar",
                    "baseline_evidence_path": "saga_reproduction/bob.txt",
                    "saga_contact_allowed": True,
                    "presaga_data_allowed": True,
                    "plaintext_released": True,
                },
                {
                    "case": "alice_mallory_contact_allowed_data_denied",
                    "baseline_evidence_path": "saga_reproduction/mallory.txt",
                    "saga_contact_allowed": True,
                    "presaga_data_allowed": False,
                    "plaintext_released": False,
                },
            ],
        )
        self._write_csv(
            tables / "mongodb_e2e_summary.csv",
            [
                {
                    "mongo_connected": True,
                    "normal_success": True,
                    "attack_blocked": True,
                    "provider_plaintext_data_visible": False,
                    "provider_plaintext_dek_visible": False,
                }
            ],
        )
        self._write_csv(
            tables / "key_custody_summary.csv",
            [
                {
                    "scenario": "umbral_owner_kms_rewrap_boundary_v1",
                    "backend": "umbral-pre-v1",
                    "request_schema_version": 1,
                    "custody_algorithm": "umbral-owner-source-key-signature-v1",
                    "custody_version": 1,
                    "custody_key_id_matches_authoritative_source": True,
                    "owner_approval_required": True,
                    "unapproved_target_rejected": True,
                    "unapproved_target_reason": "custody_request_not_approved",
                    "approval_boundary": "trusted-owner-local-input-v1",
                    "signed_artifact_verified": True,
                    "exact_retry_idempotent": True,
                    "conflicting_retry_rejected": True,
                    "conflicting_retry_reason": "custody_artifact_conflict",
                    "legacy_private_key_input_rejected": True,
                    "legacy_rejection_reason": "source_private_key_forbidden",
                    "target_decrypt_succeeded": True,
                    "provider_received_source_private_key": False,
                    "provider_saw_plaintext_dek": False,
                    "provider_secret_encodings_checked": "raw|base64|hex",
                    "provider_view_scope": "request|artifact|objects|journal|audit|results|errors",
                    "success": True,
                    "limitation": "prototype boundary fixture",
                }
            ],
        )
        for relative in EXPECTED_ARTIFACTS:
            path = root / relative
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "value\n" if path.suffix == ".csv" else "fixture\n",
                encoding="utf-8",
            )

    @staticmethod
    def _write_csv(path: Path, rows: list[dict]) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    unittest.main()

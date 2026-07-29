from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiments.release import _artifact_inventory
from experiments.release_verifier import (
    EXPECTED_ARTIFACTS,
    MANIFEST_NAME,
    source_fingerprint,
    verify_release,
)


class ReleaseEvidenceTest(unittest.TestCase):
    def test_verifier_accepts_consistent_release_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_semantic_fixture(root)
            source_hash, source_count = source_fingerprint()
            manifest = {
                "schema_version": 1,
                "status": "accepted",
                "source": {
                    "fingerprint_sha256": source_hash,
                    "file_count": source_count,
                },
                "git": {"release_inputs_dirty": False},
                "config": {
                    "values": {
                        "performance": {"policy_rule_counts": [10]},
                        "required": {
                            "blocking_attacks": 7,
                            "limitation_probes": 1,
                            "successful_tasks": 4,
                            "proverif_models": 3,
                            "saga_bridge_cases": 2,
                            "mongodb_e2e": True,
                        },
                    }
                },
                "gates": [
                    {"name": name, "passed": True}
                    for name in (
                        "blocking_attacks",
                        "prototype_limitation_probe",
                        "task_success",
                        "performance_rows",
                        "proverif_queries",
                        "saga_bridge",
                        "mongodb_e2e",
                        "release_inputs_clean",
                    )
                ],
                "artifacts": _artifact_inventory(root),
            }
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
                "attack": "toy-limitation",
                "expected_blocked": False,
                "blocked": False,
                "success": True,
                "reason": "toy_backend_public_material_recovers_dek",
                "path_kind": "provider_service_with_toy_pre",
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
            ("presaga", "provider_service", False),
        ):
            performance.append(
                {
                    "baseline": baseline,
                    "path_kind": path,
                    "cryptographic_provider_confidentiality_established": confidentiality,
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

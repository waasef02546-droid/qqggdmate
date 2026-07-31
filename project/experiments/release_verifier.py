"""Independent verification for a PRE-SAGA release evidence directory."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent
MANIFEST_NAME = "release-manifest.json"
SOURCE_PATHS = (
    "project/presaga",
    "project/experiments",
    "project/proofs",
    "project/configs",
    "project/scripts",
    "project/tests",
    "project/pyproject.toml",
    "project/README.md",
    "project/docs/traceability_matrix.md",
    "docs/adr/0008-concrete-umbral-pre-backend.md",
    "docs/adr/0009-authenticated-owner-key-custody.md",
    "docs/claims-evidence-matrix.md",
    "paper/README.md",
    "paper/pre_saga_paper.md",
    "paper/protocol_spec.md",
    "paper/submission_checklist.md",
    "saga_reproduction/saga_e2e_terminal_output.txt",
    "saga_reproduction/saga_multi_agent_terminal_output.txt",
)
EXPECTED_GATES = {
    "blocking_attacks",
    "prototype_limitation_probe",
    "concrete_provider_recovery_probe",
    "task_success",
    "performance_rows",
    "proverif_queries",
    "saga_bridge",
    "key_custody_boundary",
    "mongodb_e2e",
    "release_inputs_clean",
}
EXPECTED_ARTIFACTS = {
    "figures/latency_breakdown.svg",
    "figures/scalability_policy_rules.svg",
    "figures/task_latency_breakdown.svg",
    "figures/task_scalability.svg",
    "mongodb_e2e_report.md",
    "proofs/presaga_dek_secrecy.out.txt",
    "proofs/presaga_rekey_authentication.out.txt",
    "proofs/presaga_token_secrecy.out.txt",
    "proofs/proverif_report.md",
    "proofs/proverif_summary.csv",
    "reproducibility/release_config.yaml",
    "reproducibility/release_report.md",
    "saga_bridge_report.md",
    "tables/denial_reason_summary.csv",
    "tables/key_custody_summary.csv",
    "tables/mongodb_e2e_summary.csv",
    "tables/performance.csv",
    "tables/saga_bridge_summary.csv",
    "tables/scalability_policy_rules.csv",
    "tables/security_matrix.csv",
    "tables/task_latency_breakdown.csv",
    "tables/task_results.csv",
    "tables/task_scalability.csv",
    "tables/task_summary.csv",
}


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]
    manifest_path: Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_source_files(workspace_root: Path = WORKSPACE_ROOT) -> Iterable[Path]:
    for relative in SOURCE_PATHS:
        candidate = workspace_root / relative
        if candidate.is_file():
            yield candidate
            continue
        if not candidate.is_dir():
            raise FileNotFoundError(f"release source input is missing: {relative}")
        for path in sorted(candidate.rglob("*")):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix not in {".pyc", ".pyo"}
            ):
                yield path


def source_fingerprint(workspace_root: Path = WORKSPACE_ROOT) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in iter_source_files(workspace_root):
        relative = path.relative_to(workspace_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def verify_release(
    release_root: Path,
    *,
    workspace_root: Path = WORKSPACE_ROOT,
    check_current_source: bool = True,
) -> VerificationResult:
    release_root = release_root.resolve()
    manifest_path = release_root / MANIFEST_NAME
    errors: list[str] = []
    if not manifest_path.is_file():
        return VerificationResult(False, ("manifest_missing",), manifest_path)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return VerificationResult(
            False,
            (f"manifest_invalid:{exc}",),
            manifest_path,
        )

    if manifest.get("schema_version") != 1:
        errors.append("manifest_schema_unsupported")
    if manifest.get("status") != "accepted":
        errors.append("release_not_accepted")

    gates = manifest.get("gates", [])
    gate_names = {gate.get("name") for gate in gates}
    if gate_names != EXPECTED_GATES:
        errors.append("gate_set_mismatch")
    for gate in gates:
        if not gate.get("passed", False):
            errors.append(f"gate_failed:{gate.get('name', 'unknown')}")
    if manifest.get("git", {}).get("release_inputs_dirty", True):
        errors.append("release_inputs_not_clean")

    _verify_artifacts(release_root, manifest, errors)
    if check_current_source:
        try:
            current_fingerprint, current_count = source_fingerprint(workspace_root)
            recorded = manifest.get("source", {})
            if current_fingerprint != recorded.get("fingerprint_sha256"):
                errors.append("source_fingerprint_mismatch")
            if current_count != recorded.get("file_count"):
                errors.append("source_file_count_mismatch")
        except OSError as exc:
            errors.append(f"source_fingerprint_error:{exc}")

    _verify_semantics(release_root, manifest, errors)
    return VerificationResult(not errors, tuple(errors), manifest_path)


def _verify_artifacts(
    release_root: Path,
    manifest: dict,
    errors: list[str],
) -> None:
    artifacts = manifest.get("artifacts", [])
    artifact_paths = [artifact.get("path", "") for artifact in artifacts]
    if set(artifact_paths) != EXPECTED_ARTIFACTS:
        errors.append("artifact_set_mismatch")
    if len(artifact_paths) != len(set(artifact_paths)):
        errors.append("artifact_path_duplicate")
    for artifact in artifacts:
        relative = artifact.get("path", "")
        candidate = (release_root / relative).resolve()
        try:
            candidate.relative_to(release_root)
        except ValueError:
            errors.append(f"artifact_path_escape:{relative}")
            continue
        if not candidate.is_file():
            errors.append(f"artifact_missing:{relative}")
            continue
        if candidate.stat().st_size != artifact.get("bytes"):
            errors.append(f"artifact_size_mismatch:{relative}")
        if sha256_file(candidate) != artifact.get("sha256"):
            errors.append(f"artifact_hash_mismatch:{relative}")
        if candidate.suffix.lower() == ".csv":
            try:
                with candidate.open(newline="", encoding="utf-8") as handle:
                    row_count = sum(1 for _ in csv.DictReader(handle))
                if row_count != artifact.get("row_count"):
                    errors.append(f"artifact_row_count_mismatch:{relative}")
            except (OSError, csv.Error) as exc:
                errors.append(f"artifact_csv_error:{relative}:{exc}")


def _read_csv(release_root: Path, relative: str, errors: list[str]) -> list[dict[str, str]]:
    path = release_root / relative
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        errors.append(f"semantic_csv_error:{relative}:{exc}")
        return []


def _as_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _verify_semantics(
    release_root: Path,
    manifest: dict,
    errors: list[str],
) -> None:
    required = manifest.get("config", {}).get("values", {}).get("required", {})
    environment = manifest.get("environment", {})
    dependencies = environment.get("dependencies", {})
    backend = environment.get("crypto_backend", {})
    if dependencies.get("nucypher-core") != "0.15.0":
        errors.append("crypto_dependency_version_mismatch")
    if backend != {
        "name": "umbral-pre-v1",
        "dependency_distribution": "nucypher-core",
        "dependency_version": "0.15.0",
        "adapter_format_version": 1,
        "threshold": 1,
        "shares": 1,
    }:
        errors.append("crypto_backend_profile_mismatch")

    attacks = _read_csv(release_root, "tables/security_matrix.csv", errors)
    blocking = [row for row in attacks if _as_bool(row.get("expected_blocked"))]
    limitations = [row for row in attacks if not _as_bool(row.get("expected_blocked"))]
    if len(blocking) != required.get("blocking_attacks"):
        errors.append("attack_blocking_count_mismatch")
    if not all(
        _as_bool(row.get("blocked"))
        and _as_bool(row.get("success"))
        and row.get("path_kind") == "provider_service"
        for row in blocking
    ):
        errors.append("blocking_attack_semantics_failed")
    if len(limitations) != required.get("limitation_probes"):
        errors.append("limitation_probe_count_mismatch")
    if not all(
        not _as_bool(row.get("blocked"))
        and _as_bool(row.get("success"))
        for row in limitations
    ):
        errors.append("limitation_probe_semantics_failed")
    provider_recovery = [
        row
        for row in attacks
        if row.get("attack") == "provider_plaintext_probe"
        and _as_bool(row.get("expected_blocked"))
        and _as_bool(row.get("blocked"))
        and _as_bool(row.get("success"))
        and row.get("path_kind") == "provider_service"
        and row.get("reason") == "provider_public_material_recovery_blocked"
    ]
    if len(provider_recovery) != 1:
        errors.append("concrete_provider_recovery_probe_failed")

    tasks = _read_csv(release_root, "tables/task_results.csv", errors)
    if len(tasks) != required.get("successful_tasks") or not all(
        _as_bool(row.get("success")) for row in tasks
    ):
        errors.append("task_success_semantics_failed")

    task_latencies = _read_csv(
        release_root,
        "tables/task_latency_breakdown.csv",
        errors,
    )
    latency_by_task = {
        row.get("task"): row.get("total_latency_ms") for row in task_latencies
    }
    for task in tasks:
        try:
            if abs(
                float(task["latency_ms"])
                - float(latency_by_task.get(task.get("task"), "nan"))
            ) > 1e-9:
                errors.append(f"task_latency_cross_run:{task.get('task')}")
        except (KeyError, TypeError, ValueError):
            errors.append(f"task_latency_invalid:{task.get('task')}")

    performance = _read_csv(release_root, "tables/performance.csv", errors)
    rule_counts = (
        manifest.get("config", {})
        .get("values", {})
        .get("performance", {})
        .get("policy_rule_counts", [])
    )
    if len(performance) != len(rule_counts) * 4:
        errors.append("performance_row_count_mismatch")
    service_rows = [
        row
        for row in performance
        if row.get("baseline") == "presaga"
        and row.get("path_kind") == "provider_service"
    ]
    if len(service_rows) != len(rule_counts) or not all(
        _as_bool(row.get("provider_recovery_gate_linked"))
        for row in service_rows
    ):
        errors.append("performance_provider_boundary_mismatch")

    proofs = _read_csv(release_root, "proofs/proverif_summary.csv", errors)
    if len(proofs) != required.get("proverif_models") or not all(
        row.get("status") == "passed" and int(row.get("verified_queries", "0")) > 0
        for row in proofs
    ):
        errors.append("proof_semantics_failed")

    bridge = _read_csv(release_root, "tables/saga_bridge_summary.csv", errors)
    if len(bridge) != required.get("saga_bridge_cases"):
        errors.append("saga_bridge_count_mismatch")
    bob = next((row for row in bridge if "bob" in row.get("case", "")), None)
    mallory = next(
        (row for row in bridge if "mallory" in row.get("case", "")),
        None,
    )
    if (
        bob is None
        or not _as_bool(bob.get("saga_contact_allowed"))
        or not _as_bool(bob.get("presaga_data_allowed"))
        or not _as_bool(bob.get("plaintext_released"))
    ):
        errors.append("saga_bridge_bob_semantics_failed")
    if (
        mallory is None
        or not _as_bool(mallory.get("saga_contact_allowed"))
        or _as_bool(mallory.get("presaga_data_allowed"))
        or _as_bool(mallory.get("plaintext_released"))
    ):
        errors.append("saga_bridge_mallory_semantics_failed")
    if any(Path(row.get("baseline_evidence_path", "")).is_absolute() for row in bridge):
        errors.append("saga_bridge_absolute_evidence_path")

    custody = _read_csv(release_root, "tables/key_custody_summary.csv", errors)
    if required.get("key_custody_cases") != 1 or len(custody) != 1:
        errors.append("key_custody_boundary_count_mismatch")
    elif not (
        custody[0].get("scenario") == "umbral_owner_kms_rewrap_boundary_v1"
        and custody[0].get("backend") == "umbral-pre-v1"
        and custody[0].get("request_schema_version") == "1"
        and custody[0].get("custody_algorithm")
        == "umbral-owner-source-key-signature-v1"
        and custody[0].get("custody_version") == "1"
        and _as_bool(custody[0].get("custody_key_id_matches_authoritative_source"))
        and _as_bool(custody[0].get("owner_approval_required"))
        and _as_bool(custody[0].get("unapproved_target_rejected"))
        and custody[0].get("unapproved_target_reason")
        == "custody_request_not_approved"
        and custody[0].get("approval_boundary")
        == "trusted-owner-local-input-v1"
        and _as_bool(custody[0].get("signed_artifact_verified"))
        and _as_bool(custody[0].get("exact_retry_idempotent"))
        and _as_bool(custody[0].get("conflicting_retry_rejected"))
        and custody[0].get("conflicting_retry_reason")
        == "custody_artifact_conflict"
        and _as_bool(custody[0].get("legacy_private_key_input_rejected"))
        and custody[0].get("legacy_rejection_reason")
        == "source_private_key_forbidden"
        and _as_bool(custody[0].get("target_decrypt_succeeded"))
        and not _as_bool(custody[0].get("provider_received_source_private_key"))
        and not _as_bool(custody[0].get("provider_saw_plaintext_dek"))
        and custody[0].get("provider_secret_encodings_checked")
        == "raw|base64|hex"
        and _as_bool(custody[0].get("success"))
    ):
        errors.append("key_custody_boundary_semantics_failed")

    if required.get("mongodb_e2e"):
        mongo = _read_csv(release_root, "tables/mongodb_e2e_summary.csv", errors)
        if len(mongo) != 1:
            errors.append("mongodb_result_count_mismatch")
        elif not (
            _as_bool(mongo[0].get("mongo_connected"))
            and _as_bool(mongo[0].get("normal_success"))
            and _as_bool(mongo[0].get("attack_blocked"))
            and not _as_bool(mongo[0].get("provider_plaintext_data_visible"))
            and not _as_bool(mongo[0].get("provider_plaintext_dek_visible"))
        ):
            errors.append("mongodb_semantics_failed")

"""Authoritative, staged PRE-SAGA experiment release runner."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import yaml

from presaga.crypto.umbral_pre import UmbralPREBackend

from experiments.attacks.run_all import run_all as run_attacks
from experiments.e2e.mongodb_e2e import run_mongodb_e2e
from experiments.e2e.saga_bridge import run_saga_bridge
from experiments.evaluation.run_p3_evaluation import run_p3_evaluation
from experiments.performance.run_performance import run_performance
from experiments.release_verifier import (
    MANIFEST_NAME,
    SOURCE_PATHS,
    sha256_file,
    source_fingerprint,
    verify_release,
)
from experiments.tasks.run_all import run_all as run_tasks
from proofs.run_proverif import find_proverif, run_proofs


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "release.yaml"
DEFAULT_OUTPUT = PROJECT_ROOT / "results"


def run_release(
    *,
    config_path: Path = DEFAULT_CONFIG,
    output_root: Path = DEFAULT_OUTPUT,
    mongo_uri: str | None = None,
    mongo_db: str | None = None,
) -> tuple[Path, dict]:
    """Run in isolation, verify, then publish files with the manifest last."""

    config_path = config_path.resolve()
    output_root = output_root.resolve()
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    _validate_config(config)
    run_id = _run_id()
    staging = PROJECT_ROOT / "tmp" / "release-staging" / run_id
    staging.mkdir(parents=True, exist_ok=False)
    stages: list[dict] = []

    attack_results, _ = _stage(
        stages,
        "attacks",
        lambda: run_attacks(staging / "tables" / "security_matrix.csv"),
    )
    task_results, _ = _stage(
        stages,
        "tasks",
        lambda: run_tasks(staging / "tables" / "task_results.csv"),
    )
    performance_rows = _stage(
        stages,
        "performance",
        lambda: run_performance(
            staging,
            iterations=int(config["performance"]["iterations"]),
            rule_counts=tuple(config["performance"]["policy_rule_counts"]),
        ),
    )
    p3_outputs = _stage(
        stages,
        "task_evaluation",
        lambda: run_p3_evaluation(
            staging,
            task_results=task_results,
            attack_results=attack_results,
            scalability_iterations=int(
                config["task_scalability"]["iterations"]
            ),
        ),
    )
    proof_results = _stage(
        stages,
        "proverif",
        lambda: run_proofs(
            proofs_dir=PROJECT_ROOT / "proofs",
            output_root=staging / "proofs",
        ),
    )
    bridge_results = _stage(
        stages,
        "saga_bridge",
        lambda: run_saga_bridge(
            output_root=staging,
            workspace_root=WORKSPACE_ROOT,
        ),
    )

    mongo_result = None
    if config["required"]["mongodb_e2e"]:
        if not mongo_uri:
            raise RuntimeError(
                "release profile requires --mongo-uri; staged evidence was not published"
            )
        selected_db = mongo_db or f"presaga_release_{run_id.replace('-', '_')}"
        if not selected_db.startswith("presaga_release_"):
            raise ValueError(
                "release MongoDB name must start with 'presaga_release_'"
            )
        mongo_result = _stage(
            stages,
            "mongodb_e2e",
            lambda: run_mongodb_e2e(
                uri=mongo_uri,
                db_name=selected_db,
                output_root=staging,
            ),
        )

    gates = _evaluate_gates(
        config,
        attack_results=attack_results,
        task_results=task_results,
        performance_rows=performance_rows,
        proof_results=proof_results,
        bridge_results=bridge_results,
        mongo_result=mongo_result,
    )
    source_hash, source_count = source_fingerprint(WORKSPACE_ROOT)
    git_metadata = _git_metadata()
    gates.append(
        _gate(
            "release_inputs_clean",
            not git_metadata["release_inputs_dirty"],
            "clean" if not git_metadata["release_inputs_dirty"] else "dirty",
        )
    )
    reproducibility = staging / "reproducibility"
    reproducibility.mkdir(parents=True, exist_ok=True)
    shutil.copy2(config_path, reproducibility / "release_config.yaml")

    manifest = {
        "schema_version": 1,
        "status": "accepted" if all(gate["passed"] for gate in gates) else "rejected",
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": config["profile"],
        "source": {
            "fingerprint_sha256": source_hash,
            "file_count": source_count,
        },
        "git": git_metadata,
        "config": {
            "source_path": _portable_path(config_path),
            "sha256": sha256_file(config_path),
            "values": config,
        },
        "environment": _environment_metadata(mongo_uri),
        "stages": stages,
        "gates": gates,
        "limitations": [
            "The release backend is the prototype Umbral adapter over nucypher-core 0.15.0 (Alpha, GPLv3); it has not been independently audited and is not production cryptography.",
            "The active malicious-Provider regression finds no raw/base64/hex DEK in the exposed state, rejects direct public-key unwrap misuse, and confirms requester decryption; it is not cryptanalysis, a reduction, memory/side-channel analysis, or a whole-process guarantee.",
            "Umbral KFrags are owner/requester key-pair scoped. Provider/requester collusion and retained KFrag reuse across same-owner capsules remain outside the established claim.",
            "Trusted management-plane rotation may materialize a DEK and owner private key inside that trusted boundary; HSM/KMS isolation is not established.",
            "The SAGA bridge consumes recorded SAGA evidence and does not run a live SAGA network.",
            "MongoDB evidence is single-node local persistence and does not establish distributed transactions, RAFT, or sharding.",
            "ProVerif models cover their explicit symbolic queries only and do not verify the complete Python implementation.",
            "Artifact integrity is checked relative to the manifest; the manifest is not cryptographically signed or externally witnessed.",
        ],
    }
    _write_release_report(staging, manifest, p3_outputs)
    manifest["artifacts"] = _artifact_inventory(staging)
    (staging / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    staged_verification = verify_release(
        staging,
        workspace_root=WORKSPACE_ROOT,
        check_current_source=True,
    )
    if not staged_verification.valid:
        raise RuntimeError(
            "staged release verification failed: "
            + ",".join(staged_verification.errors)
            + f"; staging={staging}"
        )

    _publish(staging, output_root, run_id)
    published_verification = verify_release(
        output_root,
        workspace_root=WORKSPACE_ROOT,
        check_current_source=True,
    )
    if not published_verification.valid:
        raise RuntimeError(
            "published release verification failed: "
            + ",".join(published_verification.errors)
        )
    return output_root, manifest


def _validate_config(config: dict) -> None:
    if config.get("schema_version") != 1:
        raise ValueError("unsupported release config schema")
    if config.get("profile") != "full":
        raise ValueError("REL-001 accepts only the full release profile")
    for path in (
        ("performance", "iterations"),
        ("task_scalability", "iterations"),
    ):
        if int(config[path[0]][path[1]]) < 1:
            raise ValueError(f"{'.'.join(path)} must be positive")
    counts = config["performance"]["policy_rule_counts"]
    if not counts or any(int(value) < 1 for value in counts):
        raise ValueError("performance.policy_rule_counts must be positive")


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def _stage(stages: list[dict], name: str, fn: Callable):
    started = time.perf_counter()
    try:
        value = fn()
    except Exception as exc:
        stages.append(
            {
                "name": name,
                "status": "failed",
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        raise
    stages.append(
        {
            "name": name,
            "status": "passed",
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    )
    return value


def _evaluate_gates(
    config: dict,
    *,
    attack_results,
    task_results,
    performance_rows,
    proof_results,
    bridge_results,
    mongo_result,
) -> list[dict]:
    required = config["required"]
    blocking = [result for result in attack_results if result.expected_blocked]
    limitations = [
        result for result in attack_results if not result.expected_blocked
    ]
    expected_performance = (
        len(config["performance"]["policy_rule_counts"]) * 4
    )
    return [
        _gate(
            "blocking_attacks",
            len(blocking) == required["blocking_attacks"]
            and all(
                result.blocked
                and result.success
                and result.path_kind == "provider_service"
                for result in blocking
            ),
            f"{sum(result.blocked and result.success for result in blocking)}/{len(blocking)}",
        ),
        _gate(
            "prototype_limitation_probe",
            len(limitations) == required["limitation_probes"]
            and all(not result.blocked and result.success for result in limitations),
            f"{len(limitations)} active probe(s)",
        ),
        _gate(
            "concrete_provider_recovery_probe",
            len(
                [
                    result
                    for result in attack_results
                    if result.attack == "provider_plaintext_probe"
                    and result.expected_blocked
                    and result.blocked
                    and result.success
                    and result.path_kind == "provider_service"
                    and result.reason
                    == "provider_public_material_recovery_blocked"
                ]
            )
            == 1,
            "Provider exposed-state regression found no DEK, public-key unwrap was rejected, and requester decrypt verified",
        ),
        _gate(
            "task_success",
            len(task_results) == required["successful_tasks"]
            and all(result.success for result in task_results),
            f"{sum(result.success for result in task_results)}/{len(task_results)}",
        ),
        _gate(
            "performance_rows",
            len(performance_rows) == expected_performance
            and len(
                [
                    row
                    for row in performance_rows
                    if row.baseline == "presaga"
                    and row.path_kind == "provider_service"
                    and row.provider_recovery_gate_linked is True
                ]
            )
            == len(config["performance"]["policy_rule_counts"]),
            f"{len(performance_rows)}/{expected_performance}",
        ),
        _gate(
            "proverif_queries",
            len(proof_results) == required["proverif_models"]
            and all(
                result.status == "passed"
                and result.verified_queries > 0
                for result in proof_results
            ),
            ",".join(
                f"{result.proof}:{result.status}:{result.verified_queries}"
                for result in proof_results
            ),
        ),
        _gate(
            "saga_bridge",
            len(bridge_results) == required["saga_bridge_cases"]
            and bridge_results[0].plaintext_released
            and not bridge_results[1].plaintext_released
            and bridge_results[1].data_layer_decision == "deny",
            f"{len(bridge_results)} case(s)",
        ),
        _gate(
            "mongodb_e2e",
            (
                not required["mongodb_e2e"]
                or (
                    mongo_result is not None
                    and mongo_result.normal_success
                    and mongo_result.attack_blocked
                    and not mongo_result.provider_plaintext_data_visible
                    and not mongo_result.provider_plaintext_dek_visible
                )
            ),
            "required" if required["mongodb_e2e"] else "not_required",
        ),
    ]


def _gate(name: str, passed: bool, observation: str) -> dict:
    return {"name": name, "passed": bool(passed), "observation": observation}


def _artifact_inventory(root: Path) -> list[dict]:
    inventory = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == MANIFEST_NAME:
            continue
        item = {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                item["row_count"] = sum(1 for _ in csv.DictReader(handle))
        inventory.append(item)
    return inventory


def _git_metadata() -> dict:
    head = _command_output(["git", "rev-parse", "HEAD"], WORKSPACE_ROOT)
    workspace_status = _command_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        WORKSPACE_ROOT,
    )
    input_status = _command_output(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *SOURCE_PATHS,
        ],
        WORKSPACE_ROOT,
    )
    return {
        "head": head.strip(),
        "dirty": bool(input_status.strip()),
        "release_inputs_dirty": bool(input_status.strip()),
        "release_inputs_status_sha256": hashlib.sha256(
            input_status.encode("utf-8")
        ).hexdigest(),
        "workspace_dirty": bool(workspace_status.strip()),
        "workspace_status_sha256": hashlib.sha256(
            workspace_status.encode("utf-8")
        ).hexdigest(),
    }


def _environment_metadata(mongo_uri: str | None) -> dict:
    dependencies = {}
    for distribution in ("cryptography", "nucypher-core", "pymongo", "PyYAML"):
        try:
            dependencies[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            dependencies[distribution] = "not_installed"
    proverif = find_proverif(PROJECT_ROOT / "proofs")
    proverif_metadata = {"available": proverif is not None}
    if proverif:
        proverif_path = Path(proverif)
        proverif_metadata.update(
            {
                "path": _portable_path(proverif_path),
                "sha256": sha256_file(proverif_path),
                "version_output": _command_output(
                    [proverif, "-version"],
                    PROJECT_ROOT,
                    tolerate_failure=True,
                ).strip()[:500],
            }
        )
    return {
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "dependencies": dependencies,
        "crypto_backend": {
            "name": UmbralPREBackend.name,
            "dependency_distribution": UmbralPREBackend.dependency_distribution,
            "dependency_version": UmbralPREBackend.dependency_version,
            "adapter_format_version": UmbralPREBackend.adapter_format_version,
            "threshold": UmbralPREBackend.threshold,
            "shares": UmbralPREBackend.shares,
        },
        "proverif": proverif_metadata,
        "mongodb": _mongodb_metadata(mongo_uri),
    }


def _mongodb_metadata(uri: str | None) -> dict:
    if not uri:
        return {"available": False}
    try:
        from pymongo import MongoClient

        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        info = client.server_info()
        client.close()
        return {"available": True, "version": info.get("version", "unknown")}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def _command_output(
    command: list[str],
    cwd: Path,
    *,
    tolerate_failure: bool = False,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode and not tolerate_failure:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}"
        )
    return (completed.stdout or "") + (completed.stderr or "")


def _portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(WORKSPACE_ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def _write_release_report(staging: Path, manifest: dict, p3_outputs) -> None:
    lines = [
        "# PRE-SAGA authoritative release report",
        "",
        f"- Run ID: `{manifest['run_id']}`",
        f"- Profile: `{manifest['profile']}`",
        f"- Source fingerprint: `{manifest['source']['fingerprint_sha256']}`",
        f"- Git HEAD: `{manifest['git']['head']}`",
        f"- Release inputs dirty: `{manifest['git']['release_inputs_dirty']}`",
        f"- Other workspace changes present: `{manifest['git']['workspace_dirty']}`",
        f"- Task success: `{p3_outputs.task_success_rate}`",
        "",
        "## Acceptance gates",
        "",
        "| Gate | Passed | Observation |",
        "|---|---:|---|",
    ]
    for gate in manifest["gates"]:
        lines.append(
            f"| `{gate['name']}` | `{gate['passed']}` | {gate['observation']} |"
        )
    lines.extend(["", "## Evidence boundary", ""])
    lines.extend(f"- {item}" for item in manifest["limitations"])
    lines.extend(
        [
            "",
            "The JSON manifest is the authority for artifact hashes, source identity, configuration, environment, and gate results. Files not listed by that manifest are historical or auxiliary and are not part of this accepted run.",
            "",
        ]
    )
    (staging / "reproducibility" / "release_report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def _publish(staging: Path, output_root: Path, run_id: str) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    files = [
        path
        for path in sorted(staging.rglob("*"))
        if path.is_file() and path.name != MANIFEST_NAME
    ]
    files.append(staging / MANIFEST_NAME)
    for source in files:
        relative = source.relative_to(staging)
        target = output_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{run_id}.tmp")
        shutil.copy2(source, temporary)
        os.replace(temporary, target)

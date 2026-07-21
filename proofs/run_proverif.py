"""Run PRE-SAGA ProVerif artifacts and save reproducible outputs.

The runner is deliberately conservative: if the `proverif` executable is not
available, it records an environment-level `tool_unavailable` status instead of
pretending that verification succeeded.
"""

from __future__ import annotations

import csv
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


PROOF_FILES = [
    "presaga_token_secrecy.pv",
    "presaga_dek_secrecy.pv",
    "presaga_rekey_authentication.pv",
]


@dataclass(frozen=True)
class ProofRunResult:
    proof: str
    status: str
    return_code: int | None
    output_path: Path
    contribution: str


def run_proofs(
    *,
    proofs_dir: Path = Path("proofs"),
    output_root: Path = Path("results") / "proofs",
) -> list[ProofRunResult]:
    output_root.mkdir(parents=True, exist_ok=True)
    executable = shutil.which("proverif")
    results: list[ProofRunResult] = []

    for proof_name in PROOF_FILES:
        proof_path = proofs_dir / proof_name
        output_path = output_root / f"{proof_path.stem}.out.txt"
        contribution = _contribution(proof_name)
        if executable is None:
            output_path.write_text(
                "\n".join(
                    [
                        "status=tool_unavailable",
                        "tool=proverif",
                        f"proof={proof_name}",
                        "message=The proverif executable was not found on PATH; install ProVerif and rerun `python -m proofs.run_proverif`.",
                        f"architecture_contribution={contribution}",
                    ]
                ),
                encoding="utf-8",
            )
            results.append(ProofRunResult(proof_name, "tool_unavailable", None, output_path, contribution))
            continue

        completed = subprocess.run(
            [executable, str(proof_path)],
            cwd=proofs_dir.parent,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        combined = "\n".join(
            [
                f"status={'passed' if completed.returncode == 0 else 'failed'}",
                f"tool={executable}",
                f"proof={proof_name}",
                f"return_code={completed.returncode}",
                f"architecture_contribution={contribution}",
                "",
                "[stdout]",
                completed.stdout,
                "",
                "[stderr]",
                completed.stderr,
            ]
        )
        output_path.write_text(combined, encoding="utf-8")
        results.append(
            ProofRunResult(
                proof_name,
                "passed" if completed.returncode == 0 else "failed",
                completed.returncode,
                output_path,
                contribution,
            )
        )

    _write_summary(results, output_root / "proverif_summary.csv")
    _write_report(results, output_root / "proverif_report.md")
    return results


def _contribution(proof_name: str) -> str:
    return {
        "presaga_token_secrecy.pv": "Connects P1 ContactToken/DataToken layering to P2 token misuse attacks.",
        "presaga_dek_secrecy.pv": "Connects PRE transform design to provider_plaintext_probe and P3 latency visibility boundaries.",
        "presaga_rekey_authentication.pv": "Connects requester/purpose/record/version binding to P2 stale-rekey and mismatch attacks.",
    }[proof_name]


def _write_summary(results: list[ProofRunResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["proof", "status", "return_code", "output_path", "contribution"],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "proof": result.proof,
                    "status": result.status,
                    "return_code": "" if result.return_code is None else result.return_code,
                    "output_path": result.output_path.as_posix(),
                    "contribution": result.contribution,
                }
            )


def _write_report(results: list[ProofRunResult], path: Path) -> None:
    statuses = {result.status for result in results}
    lines = [
        "# P4 ProVerif execution report",
        "",
        "## Purpose",
        "",
        "This report records whether the PRE-SAGA formal artifacts were executed by ProVerif in the local environment.",
        "It is connected to the implementation and experiments rather than being a standalone appendix:",
        "",
        "- token acceptance proofs support the ContactToken/DataToken layering introduced in P1;",
        "- binding proofs support the attack matrix expanded in P2;",
        "- Provider non-plaintext visibility supports the latency/visibility evaluation reported in P3.",
        "",
        "## Results",
        "",
        "| Proof | Status | Output | Architecture contribution |",
        "|---|---|---|---|",
    ]
    for result in results:
        lines.append(
            f"| `{result.proof}` | `{result.status}` | `{result.output_path.as_posix()}` | {result.contribution} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
        ]
    )
    if statuses == {"tool_unavailable"}:
        lines.extend(
            [
                "ProVerif is not installed or not on PATH in this environment. The formal models are therefore tracked as executable artifacts, but the current run is an environment-blocked verification attempt rather than a successful proof run.",
                "",
                "To complete P4 with real verifier output, install ProVerif and rerun:",
                "",
                "```powershell",
                "python -m proofs.run_proverif",
                "```",
            ]
        )
    else:
        lines.append("At least one proof was executed by ProVerif. Inspect each output file for the verifier's query result.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    for result in run_proofs():
        print(f"{result.proof}: {result.status} -> {result.output_path}")

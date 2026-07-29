#!/usr/bin/env python3
"""Validate PRE-SAGA repository workflow control files without running core tests."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REQUIRED_FILES = (
    "AGENTS.md",
    "agens.txt",
    "README.md",
    ".editorconfig",
    ".gitattributes",
    ".codex/config.toml",
    ".codex/agents/protocol-owner.toml",
    ".codex/agents/crypto-storage-owner.toml",
    ".codex/agents/evidence-verifier.toml",
    ".agents/skills/presaga-paper-grade/SKILL.md",
    ".agents/skills/presaga-paper-grade/agents/openai.yaml",
    ".agents/skills/presaga-paper-grade/references/retest-policy.md",
    ".agents/skills/presaga-paper-grade/references/acceptance-gates.md",
    ".agents/skills/presaga-paper-grade/scripts/check_repository_hygiene.py",
    "docs/workflow/current-milestone.md",
    "docs/verification/test-ledger.yaml",
    "docs/claims-evidence-matrix.md",
    "docs/adr/0001-repository-guidance-and-evidence-control.md",
    "docs/repository/tooling-inventory.md",
    "docs/repository/layout.md",
    "docs/repository/archive-manifest.yaml",
    "docs/repository/git-baseline.md",
    "docs/repository/encoding.md",
    "archive/README.md",
)

CONTENT_RULES = {
    "AGENTS.md": (
        "Core-code priority",
        "test-ledger.yaml",
        "at most three concurrent subagents",
        "Completion gate",
    ),
    "agens.txt": (
        "不会被 Codex 自动发现",
        "$presaga-paper-grade",
        "简单验证任务与预期",
        "docs/repository/tooling-inventory.md",
    ),
    "README.md": (
        "the only authoritative PRE-SAGA engineering tree",
        "docs/repository/archive-manifest.yaml",
        "Get-Content -Encoding UTF8",
    ),
    ".codex/config.toml": (
        "max_concurrent_threads_per_session = 3",
        'default_subagent_reasoning_effort = "medium"',
    ),
    ".agents/skills/presaga-paper-grade/SKILL.md": (
        "name: presaga-paper-grade",
        "Execute a core-first work package",
        "Verify by change impact",
    ),
    "docs/workflow/current-milestone.md": (
        "Active work package",
        "State:",
        "Proposed next work package",
    ),
    "docs/verification/test-ledger.yaml": (
        "schema_version:",
        "entries:",
        "rerun_reason:",
    ),
    "docs/claims-evidence-matrix.md": (
        "Bounded claim",
        "Implementation path",
        "Status vocabulary",
    ),
    "docs/repository/tooling-inventory.md": (
        "MCP servers",
        "Installed and enabled plugins",
        "GitHub stars",
    ),
    "docs/repository/layout.md": (
        "only authoritative PRE-SAGA engineering tree",
        "Completed migration",
        "Deliberately held paths",
    ),
    "docs/repository/archive-manifest.yaml": (
        "destructive_actions: forbidden_without_explicit_user_authorization",
        "manifest_sha256:",
        "unknown_user_material",
    ),
    "docs/repository/git-baseline.md": (
        "not a commit",
        "Do not use `git add .`",
        "Clean-baseline completion condition",
    ),
    "docs/repository/encoding.md": (
        "Invalid UTF-8 files: 0",
        "Get-Content -Encoding UTF8",
    ),
}


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        path = root / relative
        if not path.is_file():
            errors.append(f"missing required file: {relative}")
            continue
        try:
            decoded = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError as error:
            errors.append(f"invalid UTF-8: {relative}: {error}")
            continue
        if "\ufffd" in decoded:
            errors.append(f"Unicode replacement character in text file: {relative}")

    for relative, required_fragments in CONTENT_RULES.items():
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "TODO" in text:
            errors.append(f"unfinished TODO marker: {relative}")
        for fragment in required_fragments:
            if fragment not in text:
                errors.append(f"missing marker in {relative}: {fragment}")

    agent_dir = root / ".codex" / "agents"
    if agent_dir.is_dir() and len(tuple(agent_dir.glob("*.toml"))) > 3:
        errors.append("more than three project subagent role files")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors = validate(root)
    if errors:
        print("CONTROL_PLANE_CHECK: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"CONTROL_PLANE_CHECK: PASS ({len(REQUIRED_FILES)} required files)")
    print("Scope: guidance/configuration only; PRE-SAGA core tests were not run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Validate CFG-002 UTF-8, canonical layout, ignore rules, and archive hashes."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import yaml


TEXT_SUFFIXES = {
    ".csv",
    ".json",
    ".md",
    ".mmd",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "runtime",
    "tools",
}


def governed_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if len(relative.parts) >= 4 and relative.parts[:2] == (".codex", "mcp") and "state" in relative.parts:
            continue
        if relative.parts[:2] == ("saga_reproduction", "saga_clean"):
            continue
        files.append(path)
    return sorted(files)


def aggregate_hash(root: Path, source: Path) -> tuple[int, int, str]:
    if source.is_file():
        payload = source.read_bytes()
        return 1, len(payload), hashlib.sha256(payload).hexdigest()

    files = sorted(path for path in source.rglob("*") if path.is_file())
    lines = []
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        total_bytes += len(payload)
        lines.append(f"{relative}|{hashlib.sha256(payload).hexdigest()}")
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    return len(files), total_bytes, digest


def validate(root: Path) -> list[str]:
    errors: list[str] = []

    for required in ("project/presaga", "project/experiments", "project/proofs", "project/tests"):
        if not (root / required).is_dir():
            errors.append(f"missing canonical directory: {required}")

    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    if "tmp/" not in gitignore:
        errors.append("tmp/ is not ignored")

    for path in governed_text_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError as error:
            errors.append(f"invalid UTF-8: {relative}: {error}")
            continue
        if "\ufffd" in text:
            errors.append(f"Unicode replacement character: {relative}")

    manifest_path = root / "docs/repository/archive-manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["entries"]:
        expected_hash = entry.get("manifest_sha256")
        if not expected_hash:
            continue
        source = root / entry["source"]
        if not source.exists():
            errors.append(f"archive source missing: {entry['source']}")
            continue
        files, total_bytes, digest = aggregate_hash(root, source)
        if files != entry["files"]:
            errors.append(f"archive file count changed: {entry['source']}: {files} != {entry['files']}")
        if total_bytes != entry["bytes"]:
            errors.append(f"archive byte count changed: {entry['source']}: {total_bytes} != {entry['bytes']}")
        if digest != expected_hash:
            errors.append(f"archive hash changed: {entry['source']}: {digest} != {expected_hash}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors = validate(root)
    if errors:
        print("REPOSITORY_HYGIENE_CHECK: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1
    count = len(governed_text_files(root))
    print(f"REPOSITORY_HYGIENE_CHECK: PASS ({count} UTF-8 text files; archive hashes stable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

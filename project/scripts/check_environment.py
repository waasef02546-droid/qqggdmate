"""Check local dependencies for PRE-SAGA strengthening work.

The script is intentionally read-only. It reports whether local tools and
optional Python packages are available before running deeper E2E experiments.
"""

from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import socket
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "project"
SAGA_REPRODUCTION = ROOT / "saga_reproduction"


PYTHON_PACKAGES = [
    "cryptography",
    "yaml",
    "pymongo",
    "fastapi",
    "uvicorn",
    "flask",
    "pydantic",
    "smolagents",
    "openai",
]


def package_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def tcp_available(host: str, port: int, timeout_seconds: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def path_status(path: Path) -> dict[str, str | bool]:
    return {
        "path": str(path),
        "exists": path.exists(),
        "type": "dir" if path.is_dir() else "file" if path.is_file() else "missing",
    }


def main() -> int:
    report = {
        "python": {
            "executable": sys.executable,
            "version": platform.python_version(),
            "version_ok": sys.version_info >= (3, 10),
            "platform": platform.platform(),
        },
        "paths": {
            "project": path_status(PROJECT),
            "tests": path_status(PROJECT / "tests"),
            "saga_official_copy": path_status(SAGA_REPRODUCTION / "saga-main"),
            "saga_clean_copy": path_status(SAGA_REPRODUCTION / "saga_clean" / "saga-main"),
            "saga_e2e_report": path_status(SAGA_REPRODUCTION / "SAGA_E2E_REPRODUCTION_RESULT.md"),
            "saga_multi_agent_report": path_status(SAGA_REPRODUCTION / "SAGA_MULTI_AGENT_REPRODUCTION_RESULT.md"),
        },
        "python_packages": {name: package_available(name) for name in PYTHON_PACKAGES},
        "services": {
            "mongodb_127_0_0_1_27017": tcp_available("127.0.0.1", 27017),
            "saga_provider_127_0_0_1_5000": tcp_available("127.0.0.1", 5000),
        },
        "tools": {
            "git": shutil.which("git") is not None,
            "proverif": shutil.which("proverif") is not None,
        },
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

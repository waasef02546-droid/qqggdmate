"""Verify the canonical PRE-SAGA release evidence and current source."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.release_verifier import verify_release


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-root",
        type=Path,
        default=PROJECT_ROOT / "results",
    )
    parser.add_argument(
        "--skip-current-source",
        action="store_true",
        help="Verify captured artifacts without comparing them to the current source tree.",
    )
    args = parser.parse_args()
    result = verify_release(
        args.release_root,
        check_current_source=not args.skip_current_source,
    )
    if result.valid:
        print(f"RELEASE_VERIFY: PASS ({result.manifest_path})")
        return 0
    print("RELEASE_VERIFY: FAIL")
    for error in result.errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

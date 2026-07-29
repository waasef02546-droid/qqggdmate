"""CLI entry point for the authoritative PRE-SAGA release runner."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.release import DEFAULT_CONFIG, DEFAULT_OUTPUT, run_release


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--mongo-uri",
        default=os.environ.get("PRESAGA_MONGODB_URI"),
    )
    parser.add_argument("--mongo-db")
    args = parser.parse_args()
    output_root, manifest = run_release(
        config_path=args.config,
        output_root=args.output_root,
        mongo_uri=args.mongo_uri,
        mongo_db=args.mongo_db,
    )
    print(f"release_status={manifest['status']}")
    print(f"release_run_id={manifest['run_id']}")
    print(f"release_root={output_root}")
    print(f"release_manifest={output_root / 'release-manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

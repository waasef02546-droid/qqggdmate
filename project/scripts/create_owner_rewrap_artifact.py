"""Create a signed owner-rotation artifact outside the Provider process.

The source private key is read from a local file containing one base64 value. It
is never accepted as a command-line value and is not included in the output.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path

from presaga.crypto.key_custody import (
    KeyCustodyError,
    OwnerRewrapApproval,
    OwnerRewrapRequest,
    UmbralOwnerKeyCustody,
)


def create_artifact(
    request_path: Path,
    approval_path: Path,
    private_key_path: Path,
) -> dict[str, object]:
    request_document = json.loads(request_path.read_text(encoding="utf-8"))
    request_payload = request_document.get("request", request_document)
    request = OwnerRewrapRequest.from_payload(request_payload)
    approval_document = json.loads(approval_path.read_text(encoding="utf-8"))
    approval_payload = approval_document.get("approval", approval_document)
    approval = OwnerRewrapApproval.from_payload(approval_payload)
    try:
        private_key = base64.b64decode(
            private_key_path.read_text(encoding="ascii").strip(),
            validate=True,
        )
    except (OSError, UnicodeError, binascii.Error) as error:
        raise KeyCustodyError("custody_private_key_file_invalid") from error
    return UmbralOwnerKeyCustody().rewrap(
        request,
        private_key,
        approval,
    ).to_payload()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a PRE-SAGA owner-rewrap artifact outside Provider custody."
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument(
        "--approval",
        type=Path,
        required=True,
        help="Owner-controlled approval JSON created independently of Provider transport.",
    )
    parser.add_argument("--source-private-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    artifact = create_artifact(
        args.request,
        args.approval,
        args.source_private_key_file,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"artifact": artifact}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

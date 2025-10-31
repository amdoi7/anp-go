#!/usr/bin/env python3
"""Python-side DID-WBA header verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Tuple

SCRIPT_DIR = Path(__file__).parent
ANP_ROOT = SCRIPT_DIR.parent.parent.parent
sys.path.insert(0, str(ANP_ROOT))


def load_json(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_required_artifacts(header_file: Path, params_file: Path) -> Tuple[str, Dict]:
    header_data = load_json(header_file)
    auth_header = header_data.get("auth_header")
    if not auth_header:
        raise ValueError(f"{header_file} does not contain auth_header")

    params = load_json(params_file)
    return auth_header, params


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify DID-WBA header using Python implementation.")
    parser.add_argument("--header-file", required=True)
    parser.add_argument("--params-file", required=True)
    parser.add_argument("--did-doc", required=True)
    parser.add_argument("--service-domain")
    args = parser.parse_args()

    try:
        from anp.authentication.did_wba import verify_auth_header_signature
    except Exception as exc:  # pragma: no cover - depends on optional deps
        print(f"Dependencies missing for Python verifier: {exc}")
        return 2

    try:
        auth_header, params = load_required_artifacts(
            Path(args.header_file),
            Path(args.params_file),
        )
        service_domain = args.service_domain or params.get("service_domain")
        if not service_domain:
            raise ValueError("Service domain is not present in params and no override was provided.")

        did_document = load_json(Path(args.did_doc))
    except Exception as exc:
        print(f"Failed to load artifacts: {exc}")
        return 1

    ok, message = verify_auth_header_signature(auth_header, did_document, service_domain)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

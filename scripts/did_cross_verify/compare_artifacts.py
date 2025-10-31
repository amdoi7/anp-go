#!/usr/bin/env python3
"""DID-WBA cross-verification helper.

Supports:
1. Optional DID document + key generation (Python implementation).
2. Optional Go/Python artifact generation.
3. Mutual header verification using both Go and Python verifiers.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).parent
GO_ROOT = SCRIPT_DIR.parent.parent
VERIFY_HELPER = SCRIPT_DIR / "verify_helper.go"
PY_VERIFY_HELPER = SCRIPT_DIR / "verify_helper.py"

try:
    from anp.authentication import create_did_wba_document
except Exception:
    create_did_wba_document = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate DID-WBA headers produced by different language implementations."
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Generate Go/Python artifacts before verifying.",
    )
    parser.add_argument(
        "--generate-did",
        action="store_true",
        help="Generate a fresh DID document and key in the artifacts directory before running generators.",
    )
    parser.add_argument(
        "--skip-generate-did",
        action="store_true",
        help="Skip DID generation even when --auto is used.",
    )
    parser.add_argument(
        "--hostname",
        default="cross-verify.agent-network",
        help="Hostname used for DID generation (with --generate-did).",
    )
    parser.add_argument(
        "--path-segments",
        default="agents,cross",
        help="Comma-separated DID path segments for DID generation.",
    )
    parser.add_argument(
        "--service-endpoint",
        default="https://cross-verify.agent-network/agents/cross",
        help="Service endpoint for DID generation.",
    )
    parser.add_argument(
        "--nonce",
        help="Fixed nonce when generating artifacts with --auto.",
    )
    parser.add_argument(
        "--timestamp",
        help="Fixed timestamp when generating artifacts with --auto.",
    )
    parser.add_argument(
        "--target",
        default="https://test.example.com/api",
        help="Target URL passed to generators when using --auto.",
    )
    parser.add_argument(
        "--did-doc",
        default=str(SCRIPT_DIR / "../../examples/did_public/public-did-doc.json"),
        help="Path to DID document JSON.",
    )
    parser.add_argument(
        "--private-key",
        default=str(SCRIPT_DIR / "../../examples/did_public/public-private-key.pem"),
        help="Path to signer private key PEM used by generators when --auto is supplied.",
    )
    parser.add_argument(
        "--go-params",
        default=str(SCRIPT_DIR / "artifacts/go_step1_params.json"),
        help="Go step1 parameters JSON.",
    )
    parser.add_argument(
        "--go-header",
        default=str(SCRIPT_DIR / "artifacts/go_step4_header.json"),
        help="Go step4 header JSON.",
    )
    parser.add_argument(
        "--py-params",
        default=str(SCRIPT_DIR / "artifacts/py_step1_params.json"),
        help="Python step1 parameters JSON.",
    )
    parser.add_argument(
        "--py-header",
        default=str(SCRIPT_DIR / "artifacts/py_step4_header.json"),
        help="Python step4 header JSON.",
    )
    return parser.parse_args()


def ensure_exists(path: Path) -> bool:
    if not path.exists():
        print(f"[missing] {path}")
        return False
    return True


def generate_did_material(
    output_dir: Path,
    hostname: str,
    segments: Sequence[str],
    service_endpoint: str,
) -> tuple[Path, Path]:
    if create_did_wba_document is None:
        raise RuntimeError("anp.authentication.create_did_wba_document is unavailable in this environment.")

    output_dir.mkdir(parents=True, exist_ok=True)
    did_document, keys = create_did_wba_document(
        hostname=hostname,
        path_segments=list(segments),
        agent_description_url=service_endpoint,
    )

    did_path = output_dir / "generated_did.json"
    did_path.write_text(json.dumps(did_document, indent=2), encoding="utf-8")

    first_fragment = next(iter(keys))
    private_bytes, public_bytes = keys[first_fragment]
    private_path = output_dir / f"{first_fragment}_private.pem"
    public_path = output_dir / f"{first_fragment}_public.pem"
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    print(f"[did] document written to {did_path}")
    print(f"[did] private key written to {private_path}")
    print(f"[did] public key written to {public_path}")

    return did_path, private_path


def run_command(label: str, cmd: Sequence[str], cwd: Path) -> bool:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if stdout:
        print(f"[{label}] {stdout}")
    if stderr:
        print(f"[{label} stderr] {stderr}")

    if result.returncode != 0:
        print(f"[fail] {label} exited with code {result.returncode}")
        return False
    return True


def run_go_verify(label: str, params: Path, header: Path, did_doc: Path) -> bool:
    cmd: Sequence[str] = (
        "go",
        "run",
        str(VERIFY_HELPER),
        "-params",
        str(params),
        "-header",
        str(header),
        "-did-doc",
        str(did_doc),
    )
    result = subprocess.run(
        cmd,
        cwd=GO_ROOT,
        capture_output=True,
        text=True,
    )
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode == 0:
        message = stdout or "verification succeeded"
        print(f"[ok] {label}: {message}")
        return True

    problem = stderr or stdout or "unknown failure"
    print(f"[fail] {label}: {problem}")
    return False


def run_python_verify(label: str, params: Path, header: Path, did_doc: Path) -> bool:
    cmd: Sequence[str] = (
        sys.executable,
        str(PY_VERIFY_HELPER),
        "--params-file",
        str(params),
        "--header-file",
        str(header),
        "--did-doc",
        str(did_doc),
    )
    result = subprocess.run(
        cmd,
        cwd=SCRIPT_DIR,
        capture_output=True,
        text=True,
    )
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode == 0:
        message = stdout or "verification succeeded"
        print(f"[ok] {label}: {message}")
        return True

    if result.returncode == 2:
        note = stderr or stdout or "python verifier unavailable"
        print(f"[skip] {label}: {note}")
        return False

    problem = stderr or stdout or "unknown failure"
    print(f"[fail] {label}: {problem}")
    return False


def main() -> None:
    args = parse_args()

    did_doc = Path(args.did_doc).resolve()
    private_key = Path(args.private_key).resolve()
    go_params = Path(args.go_params).resolve()
    go_header = Path(args.go_header).resolve()
    py_params = Path(args.py_params).resolve()
    py_header = Path(args.py_header).resolve()
    artifacts_dir = go_params.parent

    should_generate = False
    if args.generate_did:
        should_generate = True
    elif args.auto and not args.skip_generate_did and create_did_wba_document is not None:
        should_generate = True

    if should_generate:
        segments = [seg.strip() for seg in args.path_segments.split(",") if seg.strip()]
        did_doc, private_key = generate_did_material(
            artifacts_dir,
            args.hostname,
            segments,
            args.service_endpoint,
        )
        did_doc = did_doc.resolve()
        private_key = private_key.resolve()

    needed_inputs = [did_doc]
    if args.auto or args.generate_did:
        needed_inputs.append(private_key)

    if not all(ensure_exists(path) for path in needed_inputs):
        sys.exit(1)

    if args.auto:
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        go_cmd = [
            "go",
            "run",
            str(SCRIPT_DIR / "go_generator.go"),
            "-output",
            str(artifacts_dir),
            "-did-doc",
            str(did_doc),
            "-private-key",
            str(private_key),
            "-target",
            args.target,
        ]
        if args.nonce:
            go_cmd.extend(["-nonce", args.nonce])
        if args.timestamp:
            go_cmd.extend(["-timestamp", args.timestamp])

        if not run_command("go generator", go_cmd, GO_ROOT):
            sys.exit(1)

        py_cmd = [
            sys.executable,
            str(SCRIPT_DIR / "py_generator.py"),
            "--output",
            str(artifacts_dir),
            "--did-doc",
            str(did_doc),
            "--private-key",
            str(private_key),
            "--target",
            args.target,
        ]
        if args.nonce:
            py_cmd.extend(["--nonce", args.nonce])
        if args.timestamp:
            py_cmd.extend(["--timestamp", args.timestamp])

        if not run_command("python generator", py_cmd, SCRIPT_DIR):
            sys.exit(1)

    required = [did_doc, private_key, go_params, go_header, py_params, py_header, VERIFY_HELPER, PY_VERIFY_HELPER]
    if not all(ensure_exists(path) for path in required):
        sys.exit(1)

    ok_go_go = run_go_verify("go→go", go_params, go_header, did_doc)
    ok_go_py = run_go_verify("go→python", py_params, py_header, did_doc)
    ok_py_go = run_python_verify("python→go", go_params, go_header, did_doc)
    ok_py_py = run_python_verify("python→python", py_params, py_header, did_doc)

    all_ok = ok_go_go and ok_go_py and ok_py_go and ok_py_py
    if all_ok:
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()

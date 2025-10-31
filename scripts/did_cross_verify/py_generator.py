#!/usr/bin/env python3
"""Generate DID-WBA artifacts with the Python toolchain."""

import argparse
import base64
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jcs  # type: ignore
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def extract_domain(url: str) -> str:
    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]

    for char in ("/", ":"):
        idx = url.find(char)
        if idx != -1:
            return url[:idx]
    return url


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_payload(private_key: ec.EllipticCurvePrivateKey, payload: dict) -> str:
    canonical = jcs.canonicalize(payload)
    digest = hashlib.sha256(canonical).digest()

    signature_der = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature_der)
    size = (private_key.curve.key_size + 7) // 8
    signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    return base64url_encode(signature)


def write_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def generate_artifacts(
    did_doc_path: Path,
    private_key_path: Path,
    target_url: str,
    output_dir: Path,
    fixed_nonce: str | None,
    fixed_timestamp: str | None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    did_doc = json.loads(Path(did_doc_path).read_text(encoding="utf-8"))
    private_key = load_private_key(private_key_path)

    nonce = fixed_nonce or uuid.uuid4().hex
    timestamp = fixed_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    service_domain = extract_domain(target_url)

    authentication = did_doc.get("authentication", [])
    if not authentication:
        raise ValueError("DID document missing authentication methods")

    auth_entry = authentication[0]
    if isinstance(auth_entry, str):
        verification_method_id = auth_entry
    elif isinstance(auth_entry, dict):
        verification_method_id = auth_entry.get("id")
    else:
        raise ValueError("Unsupported authentication entry format")

    if not verification_method_id:
        raise ValueError("Verification method id missing in DID document")

    if "#" in verification_method_id:
        verification_fragment = verification_method_id.split("#", 1)[1]
    else:
        verification_fragment = verification_method_id

    step1 = {
        "did": did_doc["id"],
        "nonce": nonce,
        "timestamp": timestamp,
        "verification_method": verification_fragment,
        "verification_method_id": verification_method_id,
        "service_domain": service_domain,
    }
    write_json(output_dir / "py_step1_params.json", step1)
    print("✓ Step 1: Parameters generated")

    payload = {
        "nonce": nonce,
        "timestamp": timestamp,
        "service": service_domain,
        "did": did_doc["id"],
    }
    print("✓ Step 2: Payload canonicalized in memory")
    signature_base64url = sign_payload(private_key, payload)
    print("✓ Step 3: Signature calculated in memory")

    header = (
        f'DIDWba did="{step1["did"]}", '
        f'nonce="{step1["nonce"]}", '
        f'timestamp="{step1["timestamp"]}", '
        f'verification_method="{step1["verification_method"]}", '
        f'signature="{signature_base64url}"'
    )
    write_json(output_dir / "py_step4_header.json", {"auth_header": header})
    print("✓ Step 4: Auth header assembled")

    print("\n✅ Python artifacts generated successfully")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Python DID-WBA artifacts.")
    parser.add_argument(
        "--did-doc",
        default="../../examples/did_public/public-did-doc.json",
        help="Path to DID document JSON.",
    )
    parser.add_argument(
        "--private-key",
        default="../../examples/did_public/public-private-key.pem",
        help="Path to signer private key PEM.",
    )
    parser.add_argument(
        "--target",
        default="https://test.example.com/api",
        help="Target URL used for service domain inference.",
    )
    parser.add_argument("--output", default="artifacts", help="Artifacts output directory.")
    parser.add_argument("--nonce", help="Fixed nonce for reproducible output.")
    parser.add_argument("--timestamp", help="Fixed timestamp for reproducible output.")

    args = parser.parse_args()
    generate_artifacts(
        Path(args.did_doc),
        Path(args.private_key),
        args.target,
        Path(args.output),
        args.nonce,
        args.timestamp,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Offline MSAA license authority utility.

Run this only on an access-controlled issuing workstation. Never place the
generated private key in the MSAA source tree, application bundle, or build
artifacts.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mac_audit_agent.licensing.policy import (
    LICENSE_SCHEMA_VERSION,
    PRODUCT_ID,
    PROVISIONAL_LICENSOR,
)
from mac_audit_agent.licensing.verifier import canonical_json, signed_payload


def _atomic_private_write(path: Path, data: bytes) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise SystemExit(f"Refusing to overwrite existing private key: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: dict) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_bytes(canonical_json(value) + b"\n")
    os.replace(temporary, path)


def initialize(args: argparse.Namespace) -> int:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _atomic_private_write(args.private_key, private_bytes)
    trust = {
        "schema_version": 1,
        "description": "MSAA public product-license verification keys.",
        "keys": [{"key_id": args.key_id, "algorithm": "Ed25519", "public_key": base64.b64encode(public_bytes).decode("ascii"), "enabled": True}],
        "revoked_license_ids": [],
    }
    _write_json(args.public_trust_store, trust)
    print(json.dumps({"status": "CREATED", "key_id": args.key_id, "private_key": str(args.private_key.resolve()), "public_trust_store": str(args.public_trust_store.resolve()), "warning": "Back up and protect the private key outside the application repository."}, indent=2))
    return 0


def _load_private(path: Path) -> Ed25519PrivateKey:
    value = serialization.load_pem_private_key(path.expanduser().read_bytes(), password=None)
    if not isinstance(value, Ed25519PrivateKey):
        raise SystemExit("Private key is not Ed25519")
    return value


def issue(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=args.days) if args.days else None
    features = sorted(set(args.feature or []))
    document = {
        "schema_version": LICENSE_SCHEMA_VERSION,
        "product_id": PRODUCT_ID,
        "license_id": args.license_id or f"MSAA-{uuid4()}",
        "edition": args.edition.upper(),
        "licensed_to": args.licensed_to,
        "issuer": PROVISIONAL_LICENSOR,
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": expires.isoformat() if expires else None,
        "maintenance_until": expires.isoformat() if expires else None,
        "activation_mode": "offline",
        "features": features,
        "device_binding": {"fingerprint": args.device_fingerprint or ""},
    }
    signature = _load_private(args.private_key).sign(signed_payload(document))
    document["signature"] = {"algorithm": "Ed25519", "key_id": args.key_id, "value": base64.b64encode(signature).decode("ascii")}
    _write_json(args.output, document)
    print(json.dumps({"status": "ISSUED", "license_id": document["license_id"], "output": str(args.output.resolve()), "device_bound": bool(args.device_fingerprint), "features": features}, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Offline MSAA Ed25519 license authority")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Generate an offline private key and distributable public trust store.")
    init.add_argument("--private-key", type=Path, required=True)
    init.add_argument("--public-trust-store", type=Path, required=True)
    init.add_argument("--key-id", required=True)
    init.set_defaults(handler=initialize)
    create = commands.add_parser("issue", help="Issue a signed offline product license.")
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--key-id", required=True)
    create.add_argument("--licensed-to", required=True)
    create.add_argument("--edition", default="COMMERCIAL")
    create.add_argument("--days", type=int, default=365, help="Validity in days; 0 creates a perpetual license.")
    create.add_argument("--device-fingerprint")
    create.add_argument("--feature", action="append", default=[])
    create.add_argument("--license-id")
    create.add_argument("--output", type=Path, required=True)
    create.set_defaults(handler=issue)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "days", 0) < 0:
        raise SystemExit("--days must be zero or positive")
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

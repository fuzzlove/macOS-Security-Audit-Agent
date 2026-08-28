from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SIGNATURE_ALGORITHM = "ed25519"
DEFAULT_PRIVATE_KEY_PATH = Path.home() / ".msaa" / "keys" / "msaa_release_ed25519_private.pem"
DEFAULT_PUBLIC_KEY_PATH = Path("mac_audit_agent/integrity/trust/msaa_release_ed25519_public.pem")


class SigningError(RuntimeError):
    pass


def generate_keypair(private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH, public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH) -> tuple[Path, Path]:
    private_key_path = Path(private_key_path).expanduser()
    public_key_path = Path(public_key_path).expanduser()
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    _run_openssl(["genpkey", "-algorithm", "Ed25519", "-out", str(private_key_path)])
    try:
        private_key_path.chmod(0o600)
    except OSError:
        pass
    _run_openssl(["pkey", "-in", str(private_key_path), "-pubout", "-out", str(public_key_path)])
    return private_key_path, public_key_path


def load_private_key(path: Path | None = None, *, env_var: str = "MSAA_RELEASE_SIGNING_KEY") -> bytes:
    env_value = os.environ.get(env_var, "")
    if env_value:
        return env_value.encode("utf-8")
    key_path = Path(os.environ.get("MSAA_RELEASE_SIGNING_KEY_PATH", "") or path or DEFAULT_PRIVATE_KEY_PATH).expanduser()
    if not key_path.exists():
        raise SigningError("release signing private key is missing")
    return key_path.read_bytes()


def load_public_key(path: Path | None = None) -> bytes:
    key_path = Path(os.environ.get("MSAA_RELEASE_PUBLIC_KEY_PATH", "") or path or DEFAULT_PUBLIC_KEY_PATH).expanduser()
    if not key_path.exists():
        raise SigningError(f"release public key is missing: {key_path}")
    return key_path.read_bytes()


def sign_bytes(data: bytes, private_key: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="msaa-sign-") as tmp:
        tmpdir = Path(tmp)
        key = tmpdir / "private.pem"
        payload = tmpdir / "payload.bin"
        sig = tmpdir / "payload.sig"
        key.write_bytes(private_key)
        payload.write_bytes(data)
        _run_openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(payload), "-out", str(sig)])
        return sig.read_bytes()


def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="msaa-verify-") as tmp:
        tmpdir = Path(tmp)
        key = tmpdir / "public.pem"
        payload = tmpdir / "payload.bin"
        sig = tmpdir / "payload.sig"
        key.write_bytes(public_key)
        payload.write_bytes(data)
        sig.write_bytes(signature)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key), "-sigfile", str(sig), "-in", str(payload)],
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        return result.returncode == 0


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def calculate_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calculate_manifest_hash(payload: dict[str, Any]) -> str:
    copy = dict(payload)
    copy["manifest_hash"] = ""
    return hashlib.sha256(canonical_json_bytes(copy)).hexdigest()


def public_key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def sign_manifest(manifest_path: Path, *, private_key: bytes | None = None, signature_path: Path | None = None) -> Path:
    manifest_path = Path(manifest_path)
    signature_path = signature_path or manifest_path.with_suffix(".sig")
    key = private_key if private_key is not None else load_private_key()
    signature = sign_bytes(manifest_path.read_bytes(), key)
    signature_path.write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="utf-8")
    return signature_path


def verify_manifest_signature(manifest_path: Path, signature_path: Path | None = None, public_key_path: Path | None = None) -> bool:
    manifest_path = Path(manifest_path)
    signature_path = signature_path or manifest_path.with_suffix(".sig")
    if not signature_path.exists():
        return False
    try:
        signature = base64.b64decode(signature_path.read_text(encoding="utf-8").strip())
    except Exception:
        return False
    return verify_signature(manifest_path.read_bytes(), signature, load_public_key(public_key_path))


def _run_openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["openssl", *args], text=True, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise SigningError((result.stderr or result.stdout or "openssl command failed").strip())
    return result


__all__ = [
    "DEFAULT_PRIVATE_KEY_PATH",
    "DEFAULT_PUBLIC_KEY_PATH",
    "SIGNATURE_ALGORITHM",
    "SigningError",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "sign_bytes",
    "verify_signature",
    "sign_manifest",
    "verify_manifest_signature",
    "calculate_file_sha256",
    "calculate_manifest_hash",
    "canonical_json_bytes",
    "public_key_id",
]

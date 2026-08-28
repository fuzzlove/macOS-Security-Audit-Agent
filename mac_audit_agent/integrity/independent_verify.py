from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.integrity.canonical import manifest_files
from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines
from mac_audit_agent.integrity.developer_machine_signing import verify_manifest_bytes_signature
from mac_audit_agent.integrity.manifest_canonicalization import canonicalize_manifest_for_signing
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.signing import DEFAULT_PUBLIC_KEY_PATH, calculate_file_sha256, load_public_key, verify_signature


@dataclass(slots=True)
class IndependentVerificationResult:
    independent_status: str
    independent_manifest_hash: str
    independent_signature_valid: bool
    independent_file_match: bool
    mismatch_with_authority: bool
    result_code: str = ""
    mismatches: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_independent_verify(policy: str = "dev", *, root: Path | None = None, authority_status: str = "") -> IndependentVerificationResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    paths = integrity_manifest_paths(root)
    manifest_path = paths.manifest_for_policy(policy)
    signature_path = paths.signature_for_policy(policy)
    mismatches: list[str] = []
    if not manifest_path.exists():
        return IndependentVerificationResult("manifest_missing", "", False, False, True, ["manifest_missing"])
    if not signature_path.exists():
        return IndependentVerificationResult("signature_missing", "", False, False, True, ["signature_missing"])
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        bundle = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return IndependentVerificationResult("failed", "", False, False, True, "INTERNAL_ERROR", [f"manifest_parse_error:{type(exc).__name__}"])
    canonical_bytes = canonicalize_manifest_for_signing(manifest)
    manifest_hash = hashlib.sha256(canonical_bytes).hexdigest()
    signature_valid = False
    signature = base64.b64decode(str(bundle.get("signature_base64", "")))
    if bundle.get("manifest_sha256") != manifest_hash:
        mismatches.append("manifest_modified_after_signing")
    elif bundle.get("signature_model") == "trusted_release_key":
        try:
            public_key = load_public_key(root / DEFAULT_PUBLIC_KEY_PATH)
            signature_valid = verify_signature(canonical_bytes, signature, public_key)
        except Exception:
            signature_valid = False
    else:
        registry = load_trusted_developer_machines(root)
        machine = registry.find(str(bundle.get("developer_machine_id", "")))
        if machine:
            signature_valid = verify_manifest_bytes_signature(machine.public_key_pem, canonical_bytes, signature)
    declared: set[str] = set()
    for entry in manifest_files(manifest):
        rel = str(entry.get("relative_path", ""))
        if not rel:
            continue
        declared.add(rel)
        path = root / rel
        expected = str(entry.get("sha256", ""))
        if not path.exists():
            mismatches.append(f"MISSING_FILE:{rel}")
        elif calculate_file_sha256(path) != expected:
            mismatches.append(f"FILE_HASH_MISMATCH:{rel}")
    scope = build_hash_scope_report(root, policy=policy)
    for rel in sorted(set(scope.included_files) - declared):
        mismatches.append(f"UNEXPECTED_FILE:{rel}")
    file_mismatches = [item for item in mismatches if item.startswith(("MISSING_FILE:", "FILE_HASH_MISMATCH:", "UNEXPECTED_FILE:"))]
    file_match = not file_mismatches
    status = "verified" if signature_valid and file_match else "failed"
    mismatch_with_authority = bool(authority_status and status != authority_status)
    if status == "verified":
        result_code = "VALID"
    elif any(item.startswith("UNEXPECTED_FILE:") for item in file_mismatches):
        result_code = "UNEXPECTED_FILE"
    elif any(item.startswith("MISSING_FILE:") for item in file_mismatches):
        result_code = "MISSING_FILE"
    elif file_mismatches:
        result_code = "SOURCE_FILE_MODIFIED"
    else:
        result_code = "SIGNATURE_INVALID"
    return IndependentVerificationResult(status, manifest_hash, signature_valid, file_match, mismatch_with_authority, result_code, mismatches)


def run_independent_verify_subprocess(policy: str = "dev", *, root: Path | None = None, strict: bool = True, timeout_seconds: int = 60) -> IndependentVerificationResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    code_root = Path(__file__).resolve().parents[2]
    command = [
        sys.executable,
        "-m",
        "mac_audit_agent.integrity",
        "independent-verify",
        "--root",
        str(root),
        "--policy",
        policy,
        "--json",
    ]
    if strict:
        command.append("--strict")
    env = dict(os.environ)
    env["MSAA_INDEPENDENT_VERIFY_CHILD"] = "1"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(code_root) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
    try:
        completed = subprocess.run(command, cwd=code_root, env=env, text=True, capture_output=True, check=False, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return IndependentVerificationResult("failed", "", False, False, True, "INTERNAL_ERROR", ["independent_verify_timeout"], returncode=None)
    try:
        payload = json.loads(completed.stdout)
        result = IndependentVerificationResult(**payload)
    except Exception:
        result = IndependentVerificationResult("failed", "", False, False, True, "INTERNAL_ERROR", ["independent_verify_output_invalid"])
    result.stdout = completed.stdout
    result.stderr = completed.stderr
    result.returncode = completed.returncode
    if completed.returncode != 0 and "independent_verify_failed" not in result.mismatches:
        result.mismatches.append("independent_verify_failed")
    return result


__all__ = ["IndependentVerificationResult", "run_independent_verify", "run_independent_verify_subprocess"]

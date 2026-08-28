from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines
from mac_audit_agent.integrity.developer_machine_signing import (
    DeveloperMachineSigningError,
    sign_manifest_hash,
    verify_manifest_signature,
)
from mac_audit_agent.integrity.artifact_hygiene import scan_artifact_hygiene
from mac_audit_agent.integrity.headless_guard import ensure_integrity_cli_headless_safe
from mac_audit_agent.integrity.independent_verify import run_independent_verify_subprocess
from mac_audit_agent.integrity.policy_resolver import resolve_integrity_policy
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.signing import calculate_file_sha256
from mac_audit_agent.version import APP_VERSION


@dataclass(slots=True)
class ReleaseStepResult:
    status: str
    command: list[str] = field(default_factory=list)
    reason: str = ""
    stdout_tail: str = ""
    stderr_tail: str = ""
    returncode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PublicReleaseGateResult:
    status: str
    policy: str
    author: str
    reason: str
    build_id: str
    project_root: str
    source_integrity_status: str
    source_signature_status: str
    artifact_integrity_status: str
    pytest_status: str
    build_status: str
    twine_status: str
    clean_install_status: str
    runtime_artifact_hygiene_status: str
    release_ready_for_public_distribution: bool
    blocking_checks: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    source_integrity: dict[str, Any] = field(default_factory=dict)
    artifact_manifest_path: str = ""
    artifact_signature_path: str = ""
    artifact_manifest_sha256: str = ""
    evidence_path: str = ""
    steps: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_public_release_gate(
    root: Path,
    *,
    author: str,
    reason: str,
    build_id: str = "",
    developer_machine: bool = False,
    run_build: bool = False,
    run_tests: bool = False,
    run_twine_check: bool = False,
    run_clean_install: bool = False,
    sign_artifacts: bool = False,
    verify_all: bool = False,
) -> PublicReleaseGateResult:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    root = Path(root).resolve(strict=False)
    started_at = _now()
    if verify_all:
        run_build = run_tests = run_twine_check = run_clean_install = sign_artifacts = True

    policy = resolve_integrity_policy("public_release", root=root)
    steps: dict[str, ReleaseStepResult] = {}
    blockers: list[str] = []
    actions: list[str] = []

    preflight = run_integrity_preflight("pre_release", root=root, strict=True, approve_current_source=False)
    steps["headless_preflight"] = ReleaseStepResult("passed" if preflight.status == "pass" else "failed", reason="; ".join(preflight.blocking_reasons))
    if preflight.status != "pass":
        blockers.append("preflight_failed")
        actions.extend(preflight.recommended_actions or ["Fix integrity preflight blockers before public release."])

    source = repair_and_sign_integrity(
        root,
        policy="pre_release",
        author=author,
        reason=reason,
        build_id=build_id,
        developer_machine=developer_machine,
        verify_pre_uat_compatible=True,
        migrate_legacy=True,
        exclude_generated=True,
        approve_current_source=False,
        dry_run=False,
    )
    if source.status != "verified" or source.trust_state != "trusted_developer_machine_signed_manifest":
        blockers.append("source_integrity_not_trusted")
        actions.append(source.recommended_action or "Repair and sign source integrity after reviewing source changes.")

    independent_source = run_independent_verify_subprocess("pre_release", root=root, strict=True)
    steps["independent_source_verify"] = ReleaseStepResult(
        "passed" if independent_source.independent_status == "verified" and not independent_source.mismatch_with_authority else "failed",
        reason=", ".join(independent_source.mismatches),
        returncode=independent_source.returncode,
        stdout_tail=_tail(independent_source.stdout),
        stderr_tail=_tail(independent_source.stderr),
    )
    if steps["independent_source_verify"].status != "passed":
        blockers.append("independent_source_verify_failed")
        actions.append("Independent source verification must match same-process verification.")

    steps["compileall"] = _run_step([sys.executable, "-m", "compileall", "-q", "mac_audit_agent"], root)
    if steps["compileall"].status != "passed":
        blockers.append("compileall_failed")
        actions.append("Fix Python compile errors before release.")

    if run_tests:
        steps["pytest"] = _run_step([sys.executable, "-m", "pytest", "-q"], root, timeout_seconds=600)
        if steps["pytest"].status != "passed":
            blockers.append("pytest_failed")
            actions.append("Run and fix the pytest suite before public release.")
    else:
        steps["pytest"] = ReleaseStepResult("skipped", reason="not requested")

    if run_build:
        steps["build"] = _run_step([sys.executable, "-m", "build"], root, timeout_seconds=600)
        if steps["build"].status != "passed":
            blockers.append("build_failed")
            actions.append("Install build tooling and produce sdist/wheel artifacts.")
    else:
        steps["build"] = ReleaseStepResult("skipped", reason="not requested")

    dist_files = _dist_artifacts(root)
    if run_twine_check:
        if not dist_files:
            steps["twine"] = ReleaseStepResult("failed", reason="no dist artifacts found")
        else:
            steps["twine"] = _run_step([sys.executable, "-m", "twine", "check", *[str(path) for path in dist_files]], root, timeout_seconds=300)
        if steps["twine"].status != "passed":
            blockers.append("twine_check_failed")
            actions.append("Run twine check on built artifacts and fix packaging metadata.")
    else:
        steps["twine"] = ReleaseStepResult("skipped", reason="not requested")

    if run_clean_install:
        steps["clean_install"] = _run_clean_install(root, dist_files)
        if steps["clean_install"].status != "passed":
            blockers.append("clean_install_failed")
            actions.append("Verify the built wheel installs in a clean environment.")
    else:
        steps["clean_install"] = ReleaseStepResult("skipped", reason="not requested")

    hygiene_scan = scan_artifact_hygiene(root, include_dist=True)
    hygiene = ReleaseStepResult(hygiene_scan.status, reason="; ".join(hygiene_scan.blocking_reasons), stdout_tail=json.dumps(hygiene_scan.offenders))
    steps["runtime_artifact_hygiene"] = hygiene
    if hygiene_scan.status != "passed":
        blockers.append("runtime_artifact_hygiene_failed")
        actions.append("Remove runtime databases, logs, and mutable local artifacts from release outputs.")

    artifact_manifest = Path(policy.artifact_manifest_path)
    artifact_signature = Path(policy.artifact_signature_path)
    artifact_status = "skipped"
    artifact_hash = ""
    if sign_artifacts:
        if not dist_files:
            artifact_status = "failed"
            blockers.append("artifact_manifest_missing_dist")
            actions.append("Build release artifacts before signing dist integrity.")
        else:
            try:
                artifact_manifest_data = _build_artifact_manifest(root, dist_files, author=author, reason=reason, build_id=build_id)
                _write_json(artifact_manifest, artifact_manifest_data)
                artifact_hash = hashlib.sha256(_canonical_json(artifact_manifest_data)).hexdigest()
                _sign_artifact_manifest(root, artifact_manifest_data, artifact_signature, author=author, reason=reason, build_id=build_id)
                artifact_status = "verified" if _verify_artifact_signature(root, artifact_manifest, artifact_signature) else "failed"
            except Exception as exc:
                artifact_status = "failed"
                steps["artifact_signing"] = ReleaseStepResult("failed", reason=f"{type(exc).__name__}: {exc}")
            if artifact_status != "verified":
                blockers.append("artifact_signature_invalid")
                actions.append("Regenerate and sign dist artifact manifest on the exact upload artifacts.")
    else:
        steps["artifact_signing"] = ReleaseStepResult("skipped", reason="not requested")

    required_release_steps = {
        "pytest": "pytest_not_run",
        "build": "build_not_run",
        "twine": "twine_check_not_run",
        "clean_install": "clean_install_not_run",
    }
    for step_name, blocker in required_release_steps.items():
        if steps[step_name].status == "skipped":
            blockers.append(blocker)
            actions.append("Run public-release-gate with --verify-all before public distribution.")
    if not sign_artifacts:
        blockers.append("artifact_signing_not_run")
        actions.append("Run public-release-gate with --sign-artifacts or --verify-all.")

    ready = not blockers and source.status == "verified" and artifact_status == "verified"
    result = PublicReleaseGateResult(
        status="verified" if ready else "blocked",
        policy="public_release",
        author=author,
        reason=reason,
        build_id=build_id,
        project_root=str(root),
        source_integrity_status=source.status,
        source_signature_status=source.trust_state,
        artifact_integrity_status=artifact_status,
        pytest_status=steps["pytest"].status,
        build_status=steps["build"].status,
        twine_status=steps["twine"].status,
        clean_install_status=steps["clean_install"].status,
        runtime_artifact_hygiene_status=hygiene.status,
        release_ready_for_public_distribution=ready,
        blocking_checks=sorted(set(blockers)),
        recommended_actions=sorted(set(action for action in actions if action)),
        source_integrity=source.to_dict(),
        artifact_manifest_path=str(artifact_manifest),
        artifact_signature_path=str(artifact_signature),
        artifact_manifest_sha256=artifact_hash,
        steps={key: value.to_dict() for key, value in steps.items()},
    )
    result.evidence_path = str(_write_evidence(result, started_at=started_at))
    return result


def _run_step(command: list[str], root: Path, *, timeout_seconds: int = 120) -> ReleaseStepResult:
    try:
        completed = subprocess.run(command, cwd=root, text=True, capture_output=True, check=False, timeout=timeout_seconds)
    except FileNotFoundError as exc:
        return ReleaseStepResult("failed", command=command, reason=str(exc))
    except subprocess.TimeoutExpired:
        return ReleaseStepResult("failed", command=command, reason=f"timed out after {timeout_seconds}s")
    status = "passed" if completed.returncode == 0 else "failed"
    return ReleaseStepResult(
        status,
        command=command,
        reason="" if status == "passed" else "command returned non-zero",
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
        returncode=completed.returncode,
    )


def _run_clean_install(root: Path, dist_files: list[Path]) -> ReleaseStepResult:
    wheels = sorted((path for path in dist_files if path.suffix == ".whl"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not wheels:
        return ReleaseStepResult("failed", reason="no wheel artifact found")
    with tempfile.TemporaryDirectory(prefix="msaa-clean-install-") as tmp:
        venv = Path(tmp) / "venv"
        created = _run_step([sys.executable, "-m", "venv", str(venv)], root, timeout_seconds=180)
        if created.status != "passed":
            return created
        python = venv / "bin" / "python"
        installed = _run_step([str(python), "-m", "pip", "install", "--no-index", "--find-links", str(root / "dist"), str(wheels[0])], root, timeout_seconds=300)
        if installed.status != "passed":
            return installed
        return _run_step([str(python), "-c", "import mac_audit_agent; print('clean install ok')"], root)


def _dist_artifacts(root: Path) -> list[Path]:
    dist = root / "dist"
    if not dist.exists():
        return []
    excluded = {"MSAA_RELEASE_ARTIFACTS.json", "MSAA_RELEASE_ARTIFACTS.signature.json"}
    return sorted(path for path in dist.iterdir() if path.is_file() and path.name not in excluded)


def _build_artifact_manifest(root: Path, files: list[Path], *, author: str, reason: str, build_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "project_name": "macOS Security Audit Agent",
        "app_version": APP_VERSION,
        "policy": "public_release",
        "build_id": build_id,
        "generated_at": _now(),
        "author": author,
        "reason": reason,
        "hash_algorithm": "sha256",
        "artifacts": [
            {
                "relative_path": path.relative_to(root).as_posix(),
                "sha256": calculate_file_sha256(path),
                "size": path.stat().st_size,
            }
            for path in files
        ],
    }


def _sign_artifact_manifest(root: Path, manifest: dict[str, Any], signature_path: Path, *, author: str, reason: str, build_id: str) -> None:
    registry = load_trusted_developer_machines(root)
    active = registry.active_machines()
    if not active:
        raise DeveloperMachineSigningError("developer machine is not enrolled")
    manifest_hash = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    signature = sign_manifest_hash(root, manifest_hash)
    machine = active[0]
    bundle = {
        "signature_schema_version": 1,
        "project_name": "macOS Security Audit Agent",
        "manifest_path": "dist/MSAA_RELEASE_ARTIFACTS.json",
        "manifest_sha256": manifest_hash,
        "signed_at": _now(),
        "policy": "public_release",
        "build_id": build_id,
        "app_version": APP_VERSION,
        "author": author,
        "reason": reason,
        "signer_type": "developer_machine",
        "developer_machine_id": machine.developer_machine_id,
        "public_key_fingerprint_sha256": machine.public_key_fingerprint_sha256,
        "signature_algorithm": "ECDSA-P256-SHA256",
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "verification_status": "unchecked",
        "limitations": [
            "Artifact signing verifies local release files only and is not notarization.",
            "Developer-machine signing is readiness evidence, not government certification.",
        ],
    }
    _write_json(signature_path, bundle)


def _verify_artifact_signature(root: Path, manifest_path: Path, signature_path: Path) -> bool:
    if not manifest_path.exists() or not signature_path.exists():
        return False
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bundle = json.loads(signature_path.read_text(encoding="utf-8"))
    if hashlib.sha256(_canonical_json(manifest)).hexdigest() != bundle.get("manifest_sha256"):
        return False
    registry = load_trusted_developer_machines(root)
    machine = registry.find(str(bundle.get("developer_machine_id", "")))
    if machine is None or machine.trust_status != "active":
        return False
    try:
        signature = base64.b64decode(str(bundle.get("signature_base64", "")))
    except Exception:
        return False
    return verify_manifest_signature(machine.public_key_pem, str(bundle.get("manifest_sha256", "")), signature)


def _runtime_artifact_hygiene(root: Path, dist_files: list[Path]) -> ReleaseStepResult:
    bad_suffixes = (".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite3-wal", ".sqlite-shm", ".sqlite3-shm", ".db", ".log")
    offenders = [path.relative_to(root).as_posix() for path in dist_files if path.name.endswith(bad_suffixes)]
    if offenders:
        return ReleaseStepResult("failed", reason="runtime artifacts found in dist", stdout_tail=json.dumps(offenders))
    return ReleaseStepResult("passed")


def _write_evidence(result: PublicReleaseGateResult, *, started_at: str) -> Path:
    evidence_dir = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "release_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    path = evidence_dir / f"public_release_gate_{timestamp}.json"
    payload = result.to_dict() | {"command": "python -m mac_audit_agent.integrity public-release-gate", "started_at": started_at, "completed_at": _now()}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _tail(text: str, max_chars: int = 4000) -> str:
    text = text or ""
    return text[-max_chars:]


def _now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = ["PublicReleaseGateResult", "ReleaseStepResult", "run_public_release_gate"]

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import git_output, rehash_manifest, utc_now_iso, verify_manifest, write_audit_record
from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines
from mac_audit_agent.integrity.developer_machine_signing import (
    DeveloperMachineSigningError,
    require_developer_machine_signing_key,
    sign_canonical_manifest,
)
from mac_audit_agent.integrity.headless_guard import ensure_integrity_cli_headless_safe
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report, classify_integrity_metadata_path
from mac_audit_agent.integrity.independent_verify import run_independent_verify_subprocess
from mac_audit_agent.integrity.manifest_discovery import ManifestDiscoveryResult, discover_integrity_manifests
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.result_cache import build_current_integrity_status, write_current_integrity_status, write_current_integrity_status_db
from mac_audit_agent.integrity.signing import calculate_file_sha256
from mac_audit_agent.integrity.source_change_approval import write_source_change_approval
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status


class AutoSignError(RuntimeError):
    pass


@dataclass(slots=True)
class AutoSignResult:
    status: str
    trust_state: str
    policy: str
    author: str
    reason: str
    build_id: str
    project_root: str
    canonical_manifest_path: str
    signature_path: str
    developer_machine_id: str = ""
    public_key_fingerprint: str = ""
    manifest_sha256: str = ""
    source_modified_files: list[str] = field(default_factory=list)
    generated_modified_files: list[str] = field(default_factory=list)
    trust_metadata_files: list[str] = field(default_factory=list)
    legacy_ignored_files: list[str] = field(default_factory=list)
    deprecated_artifacts: list[str] = field(default_factory=list)
    excluded_files_count: int = 0
    checked_files_count: int = 0
    signature_valid: bool = False
    file_match_status: str = "not_checked"
    pre_uat_compatible: bool = False
    pre_uat_checked_by_exact_function: bool = False
    pre_uat_check_ids: list[str] = field(default_factory=list)
    pre_uat_result_status: str = ""
    pre_uat_result_trust_state: str = ""
    integrity_unknown: bool = False
    can_auto_repair: bool = False
    requires_developer_approval: bool = False
    evidence_path: str = ""
    error: str = ""
    recommended_action: str = ""
    discovery: dict[str, Any] = field(default_factory=dict)
    consumer_comparison: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def auto_sign_integrity(
    root: Path,
    *,
    policy: str = "dev",
    author: str,
    reason: str,
    build_id: str = "",
    developer_machine: bool = False,
    verify_pre_uat_compatible: bool = True,
    migrate_legacy: bool = True,
    exclude_generated: bool = True,
    approve_current_source: bool = False,
    typed_confirmation: str = "",
    dry_run: bool = False,
    audit_log: Path | None = None,
    evidence_prefix: str = "auto_sign_evidence",
    command_label: str = "python -m mac_audit_agent.integrity auto-sign",
) -> AutoSignResult:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=False)
    if not developer_machine:
        raise AutoSignError("--developer-machine is required for trusted auto-sign")
    policy = normalize_policy(policy)
    root = Path(root).resolve(strict=False)
    paths = integrity_manifest_paths(root)
    started_at = utc_now_iso()
    discovery = discover_integrity_manifests(root)
    if migrate_legacy:
        _migrate_legacy_if_safe(root, discovery)
        discovery = discover_integrity_manifests(root)

    pre_summary = verify_manifest(root, manifest_path=paths.canonical_manifest, signature_path=paths.canonical_signature_bundle, policy=policy) if paths.canonical_manifest.exists() else None
    source_drift = _source_drift(pre_summary)
    drift = _classified_drift(root)
    generated_drift = drift["generated_modified_files"]
    preflight = run_integrity_preflight(policy, root=root, strict=True, approve_current_source=approve_current_source)
    hash_scope = build_hash_scope_report(root, policy=policy)
    if source_drift and not approve_current_source:
        status = resolve_integrity_status(policy, root=root)
        result = AutoSignResult(
            status="failed",
            trust_state="source_files_modified",
            policy=policy,
            author=author,
            reason=reason,
            build_id=build_id,
            project_root=str(root),
            canonical_manifest_path=str(paths.canonical_manifest),
            signature_path=str(paths.canonical_signature_bundle),
            source_modified_files=source_drift,
            generated_modified_files=generated_drift,
            trust_metadata_files=drift["trust_metadata_files"],
            legacy_ignored_files=drift["legacy_ignored_files"],
            deprecated_artifacts=drift["deprecated_artifacts"],
            pre_uat_compatible=False,
            integrity_unknown=False,
            can_auto_repair=False,
            requires_developer_approval=True,
            error="real source changes require --approve-current-source",
            recommended_action="Review source changes, then rerun auto-sign with --approve-current-source if approved.",
            discovery=discovery.to_dict(),
        )
        result.evidence_path = str(_write_evidence(result, started_at=started_at, evidence_prefix=evidence_prefix, command_label=command_label))
        return result
    if source_drift and approve_current_source and typed_confirmation != "APPROVE SOURCE BASELINE":
        raise AutoSignError("source changes require typed confirmation: APPROVE SOURCE BASELINE")

    registry = load_trusted_developer_machines(root)
    active = registry.active_machines()
    if not active:
        result = AutoSignResult(
            status="failed",
            trust_state="developer_machine_not_enrolled",
            policy=policy,
            author=author,
            reason=reason,
            build_id=build_id,
            project_root=str(root),
            canonical_manifest_path=str(paths.canonical_manifest),
            signature_path=str(paths.canonical_signature_bundle),
            generated_modified_files=generated_drift,
            trust_metadata_files=drift["trust_metadata_files"],
            legacy_ignored_files=drift["legacy_ignored_files"],
            deprecated_artifacts=drift["deprecated_artifacts"],
            integrity_unknown=False,
            can_auto_repair=False,
            requires_developer_approval=False,
            error="developer machine is not enrolled",
            recommended_action="Run integrity machine enroll, then rerun auto-sign.",
            discovery=discovery.to_dict(),
        )
        result.evidence_path = str(_write_evidence(result, started_at=started_at, evidence_prefix=evidence_prefix, command_label=command_label))
        return result

    try:
        signing_machine = require_developer_machine_signing_key(root)
    except DeveloperMachineSigningError as exc:
        result = AutoSignResult(
            status="failed",
            trust_state="developer_signing_key_missing",
            policy=policy,
            author=author,
            reason=reason,
            build_id=build_id,
            project_root=str(root),
            canonical_manifest_path=str(paths.canonical_manifest),
            signature_path=str(paths.canonical_signature_bundle),
            generated_modified_files=generated_drift,
            trust_metadata_files=drift["trust_metadata_files"],
            legacy_ignored_files=drift["legacy_ignored_files"],
            deprecated_artifacts=drift["deprecated_artifacts"],
            integrity_unknown=False,
            can_auto_repair=False,
            error=str(exc),
            recommended_action="Restore the enrolled developer-machine private key or enroll a new trusted developer machine, then rerun auto-sign.",
            discovery=discovery.to_dict(),
        )
        result.evidence_path = str(_write_evidence(result, started_at=started_at, evidence_prefix=evidence_prefix, command_label=command_label))
        return result

    if dry_run:
        status = resolve_integrity_status(policy, root=root)
        result = _result_from_status(status, policy=policy, author=author, reason=reason, build_id=build_id, drift=drift, discovery=discovery)
        result.status = "repairable" if result.status != "verified" else result.status
        result.can_auto_repair = True
        result.evidence_path = str(_write_evidence(result, started_at=started_at, evidence_prefix=evidence_prefix, command_label=command_label))
        return result

    if preflight.status != "pass":
        result = AutoSignResult(
            status="failed",
            trust_state="preflight_failed",
            policy=policy,
            author=author,
            reason=reason,
            build_id=build_id,
            project_root=str(root),
            canonical_manifest_path=str(paths.canonical_manifest),
            signature_path=str(paths.canonical_signature_bundle),
            generated_modified_files=generated_drift,
            trust_metadata_files=drift["trust_metadata_files"],
            legacy_ignored_files=drift["legacy_ignored_files"],
            deprecated_artifacts=drift["deprecated_artifacts"],
            integrity_unknown=False,
            can_auto_repair=False,
            requires_developer_approval=not approve_current_source and preflight.source_change_status == "unapproved_source_changes",
            error="; ".join(preflight.blocking_reasons),
            recommended_action="; ".join(preflight.recommended_actions) or preflight.recommended_command,
            discovery=discovery.to_dict(),
        )
        result.evidence_path = str(_write_evidence(result, started_at=started_at, evidence_prefix=evidence_prefix, command_label=command_label, extra={"preflight": preflight.to_dict(), "hash_scope": hash_scope.to_dict()}))
        return result

    approval = None
    if source_drift and approve_current_source:
        approval = write_source_change_approval(
            root,
            approved_by=author,
            reason=reason,
            build_id=build_id,
            changed_files=source_drift,
            policy=policy,
            command=command_label,
        )
    manifest, _diff = rehash_manifest(
        root,
        author=author,
        reason=reason,
        build_id=build_id,
        developer_mode=True,
        sign=False,
        audit_log=audit_log,
        policy=policy,
    )
    signature = sign_canonical_manifest(
        root,
        manifest_path=manifest,
        policy=policy,
        author=author,
        reason=reason,
        build_id=build_id,
        developer_machine_id=signing_machine.developer_machine_id,
    )
    status = resolve_integrity_status(policy, root=root)
    independent = run_independent_verify_subprocess(policy, root=root, strict=True)
    if independent.independent_status != "verified" or independent.mismatch_with_authority or independent.returncode not in {0, None}:
        raise AutoSignError("independent post-sign verification failed: " + ", ".join(independent.mismatches))
    result = _result_from_status(status, policy=policy, author=author, reason=reason, build_id=build_id, drift=drift, discovery=discovery)
    result.signature_path = str(signature)
    result.manifest_sha256 = calculate_file_sha256(manifest) if manifest.exists() else ""
    result.file_match_status = "verified" if not status.modified_files and not status.missing_files and not status.extra_files else "failed"
    result.pre_uat_compatible = bool(status.pre_uat_compatible) if verify_pre_uat_compatible else result.status == "verified"
    result.integrity_unknown = "unknown" in result.trust_state
    if status.signer_status:
        signer = status.signer_status[0]
        result.developer_machine_id = str(signer.get("developer_machine_id", ""))
    result.public_key_fingerprint = signing_machine.public_key_fingerprint_sha256
    current_status = build_current_integrity_status(status, root=root)
    write_current_integrity_status(current_status, root=root)
    consumer_comparison: dict[str, Any] = {}
    try:
        from mac_audit_agent.integrity.consumer_compare import compare_integrity_consumers

        comparison = compare_integrity_consumers(root, policy=policy)
        consumer_comparison = comparison.to_dict()
        result.consumer_comparison = consumer_comparison
        pre_uat = next((consumer for consumer in comparison.consumers if consumer.name == "pre_uat_integrity"), None)
        if verify_pre_uat_compatible:
            result.pre_uat_compatible = bool(pre_uat and pre_uat.status == result.status and pre_uat.trust_state == result.trust_state)
            result.pre_uat_checked_by_exact_function = bool(pre_uat)
            result.pre_uat_check_ids = list((pre_uat.details or {}).get("check_ids", []) if pre_uat else [])
            result.pre_uat_result_status = pre_uat.status if pre_uat else "not_checked"
            result.pre_uat_result_trust_state = pre_uat.trust_state if pre_uat else ""
        if comparison.status != "pass":
            result.recommended_action = "Integrity core verification succeeded, but one or more consumers still report stale or divergent integrity errors."
            result.error = "; ".join(comparison.mismatches[:5])
    except Exception as exc:
        consumer_comparison = {"status": "error", "failure_code": "INTEGRITY_CONSUMER_DIVERGENCE", "error": f"{type(exc).__name__}: {exc}"}
        result.consumer_comparison = consumer_comparison
        if verify_pre_uat_compatible:
            result.pre_uat_compatible = False
        result.recommended_action = "Integrity core verification succeeded, but consumer comparison could not complete."
        result.error = consumer_comparison["error"]
    result.evidence_path = str(_write_evidence(
        result,
        started_at=started_at,
        evidence_prefix=evidence_prefix,
        command_label=command_label,
        extra={"preflight": preflight.to_dict(), "hash_scope": hash_scope.to_dict(), "independent_verify": independent.to_dict(), "source_approval": approval.to_dict() if approval else {}, "consumer_comparison": consumer_comparison},
    ))
    current_status.evidence_path = result.evidence_path
    current_status.recommended_action = result.recommended_action
    write_current_integrity_status(current_status, root=root)
    try:
        write_current_integrity_status_db(current_status, consumer_compare_status=str(consumer_comparison.get("status", "")))
    except Exception:
        pass
    write_audit_record(
        action="auto-sign",
        status=result.status,
        root=root,
        audit_log=audit_log,
        author=author,
        reason=reason,
        details=result.to_dict(),
    )
    return result


def _result_from_status(status, *, policy: str, author: str, reason: str, build_id: str, drift: dict[str, list[str]], discovery: ManifestDiscoveryResult) -> AutoSignResult:
    manifest_source_mismatches = sorted({*(status.modified_files or []), *(status.missing_files or []), *(status.extra_files or [])})
    return AutoSignResult(
        status=status.status,
        trust_state=status.trust_state,
        policy=policy,
        author=author,
        reason=reason,
        build_id=build_id,
        project_root=str(Path(status.canonical_manifest_path).parents[2]) if status.canonical_manifest_path else "",
        canonical_manifest_path=status.canonical_manifest_path,
        signature_path=status.signature_path,
        source_modified_files=[] if status.status == "verified" else manifest_source_mismatches,
        generated_modified_files=drift["generated_modified_files"] or list(status.generated_modified_files),
        trust_metadata_files=drift["trust_metadata_files"],
        legacy_ignored_files=drift["legacy_ignored_files"],
        deprecated_artifacts=drift["deprecated_artifacts"],
        excluded_files_count=len(status.excluded_files),
        checked_files_count=status.checked_files,
        signature_valid=status.signature_valid is True,
        file_match_status="verified" if not status.modified_files and not status.missing_files and not status.extra_files else "failed",
        pre_uat_compatible=status.pre_uat_compatible,
        integrity_unknown="unknown" in status.trust_state,
        can_auto_repair=status.trust_state in {"signature_missing", "generated_artifact_out_of_scope"},
        requires_developer_approval=status.trust_state == "source_files_modified",
        recommended_action=status.recommended_action,
        discovery=discovery.to_dict(),
    )


def _source_drift(summary) -> list[str]:
    if summary is None:
        return []
    return sorted({*(item.relative_path for item in summary.modified_files), *(item.relative_path for item in summary.missing_files), *(item.relative_path for item in summary.unexpected_files)})


def _generated_drift(root: Path) -> list[str]:
    return _classified_drift(root)["generated_modified_files"]


def _classified_drift(root: Path) -> dict[str, list[str]]:
    try:
        output = git_output(["status", "--porcelain"], root)
    except Exception:
        return {"generated_modified_files": [], "trust_metadata_files": [], "legacy_ignored_files": [], "deprecated_artifacts": []}
    drift: dict[str, list[str]] = {"generated_modified_files": [], "trust_metadata_files": [], "legacy_ignored_files": [], "deprecated_artifacts": []}
    from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path

    for line in output.splitlines():
        rel = line[3:].strip() if len(line) > 3 else line.strip()
        rel = rel.strip('"')
        if not rel:
            continue
        metadata = classify_integrity_metadata_path(rel)
        if metadata == "trust_metadata":
            drift["trust_metadata_files"].append(rel)
        elif metadata == "legacy_ignored":
            drift["legacy_ignored_files"].append(rel)
        elif metadata == "deprecated_artifact":
            drift["deprecated_artifacts"].append(rel)
        elif is_runtime_mutable_path(rel, default_excluded_patterns()):
            drift["generated_modified_files"].append(rel)
    return {key: sorted(set(value)) for key, value in drift.items()}


def _migrate_legacy_if_safe(root: Path, discovery: ManifestDiscoveryResult) -> None:
    paths = integrity_manifest_paths(root)
    if paths.canonical_manifest.exists() or discovery.recommended_action != "migrate_legacy" or len(discovery.legacy_candidates) != 1:
        return
    legacy = Path(discovery.legacy_candidates[0])
    if not legacy.exists():
        return
    try:
        legacy.relative_to(root)
    except ValueError:
        return
    backup = legacy.with_suffix(legacy.suffix + ".migrated.bak")
    if not backup.exists():
        shutil.copy2(legacy, backup)
    paths.canonical_manifest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(legacy, paths.canonical_manifest)


def _evidence_dir() -> Path:
    base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity" / "signing_evidence"
    try:
        base.mkdir(parents=True, exist_ok=True)
        probe = base / ".write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return base
    except OSError:
        fallback = Path("/tmp/msaa_integrity")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _write_evidence(
    result: AutoSignResult,
    *,
    started_at: str,
    evidence_prefix: str = "auto_sign_evidence",
    command_label: str = "python -m mac_audit_agent.integrity auto-sign",
    extra: dict[str, Any] | None = None,
) -> Path:
    completed_at = utc_now_iso()
    safe_prefix = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in evidence_prefix).strip("_") or "auto_sign_evidence"
    path = _evidence_dir() / f"{safe_prefix}_{completed_at.replace(':', '').replace('-', '')}.json"
    payload = result.to_dict() | {
        "command": command_label,
        "started_at": started_at,
        "completed_at": completed_at,
        **(extra or {}),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


__all__ = ["AutoSignError", "AutoSignResult", "auto_sign_integrity"]

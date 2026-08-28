from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import shlex
import sys

from mac_audit_agent.integrity.artifact_hygiene import scan_artifact_hygiene
from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.failure_codes import IntegrityFailureCode
from mac_audit_agent.integrity.git_gate import evaluate_git_gate
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.headless_sentinel import isolated_integrity_import_check
from mac_audit_agent.integrity.path_consensus import verify_manifest_path_consensus
from mac_audit_agent.runtime.python_runtime_gate import evaluate_python_runtime


@dataclass(slots=True)
class IntegrityPreflightResult:
    status: str
    policy: str
    python_executable: str
    python_version: str
    headless_safe: bool
    gui_modules_loaded: list[str]
    canonical_manifest_path: str
    canonical_signature_path: str
    legacy_manifest_candidates: list[str]
    source_scope_file_count: int
    excluded_file_count: int
    generated_artifact_count: int
    source_modified_files: list[str]
    generated_modified_files: list[str]
    path_consistency: dict[str, object]
    generated_exclusion_status: str
    source_change_status: str
    gui_import_status: str
    pre_uat_verifier_match: bool
    release_verifier_match: bool
    blocking_reasons: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    failure_codes: list[str] = field(default_factory=list)
    recommended_command: str = ""
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_integrity_preflight(policy: str = "dev", *, root: Path | None = None, strict: bool = False, approve_current_source: bool = False) -> IntegrityPreflightResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    authority = IntegrityAuthority(root, policy)
    resolution = authority.resolve_policy()
    consensus = verify_manifest_path_consensus(policy, root=root)
    git_gate = evaluate_git_gate(root, approve_current_source=approve_current_source)
    sentinel = isolated_integrity_import_check()
    runtime = evaluate_python_runtime()
    scope = build_hash_scope_report(root, policy=policy)
    hygiene = scan_artifact_hygiene(root, include_dist=False)
    blockers: list[str] = []
    warnings: list[str] = []
    failure_codes: list[str] = []
    if not consensus.consensus:
        blockers.append("manifest_path_consensus_failed")
        failure_codes.append(IntegrityFailureCode.POLICY_PATH_DIVERGENCE.value)
    if git_gate.status != "passed":
        blockers.extend(git_gate.blocking_reasons or ["unapproved_source_changes"])
        failure_codes.append(IntegrityFailureCode.SOURCE_FILE_MODIFIED.value)
    if not sentinel.headless_safe:
        blockers.append("gui_modules_imported")
        failure_codes.append(IntegrityFailureCode.HEADLESS_GUI_IMPORT.value)
    if not runtime.supported_for_integrity_cli:
        blockers.append("unsupported_python_runtime")
        failure_codes.append(IntegrityFailureCode.UNKNOWN_UNCLASSIFIED_ERROR.value)
    if scope.dangerous_unclassified_files:
        reason = "unclassified source-scope files require classification"
        if strict:
            blockers.append(reason)
            failure_codes.append(IntegrityFailureCode.UNKNOWN_UNCLASSIFIED_ERROR.value)
        else:
            warnings.append(reason)
    if hygiene.status != "passed":
        blockers.append("artifact_hygiene_failed")
        failure_codes.append(IntegrityFailureCode.ARTIFACT_HYGIENE_FAIL.value)
    if any(item.endswith("integrity_manifest.json") for item in scope.included_files):
        blockers.append("manifest_self_reference_in_hash_scope")
        failure_codes.append(IntegrityFailureCode.UNKNOWN_UNCLASSIFIED_ERROR.value)
    status = "fail" if blockers else "warning" if warnings else "pass"
    recommended = []
    if blockers or warnings:
        recommended.append("Review preflight blockers before hashing or signing.")
    if git_gate.status != "passed":
        recommended.append("Use --approve-current-source with typed confirmation only after source review.")
    if not consensus.consensus:
        recommended.append("Repair manifest policy routing before signing.")
    return IntegrityPreflightResult(
        status=status,
        policy=authority.policy,
        python_executable=runtime.python_executable,
        python_version=runtime.python_version,
        headless_safe=sentinel.headless_safe,
        gui_modules_loaded=sentinel.imported_gui_modules,
        canonical_manifest_path=resolution.source_manifest_path,
        canonical_signature_path=resolution.source_signature_path,
        legacy_manifest_candidates=authority.discover_legacy_manifests().discovered_legacy_manifests,
        source_scope_file_count=len(scope.included_files),
        excluded_file_count=len(scope.excluded_files),
        generated_artifact_count=len(scope.generated_files) + len(scope.runtime_files) + len(scope.build_files),
        source_modified_files=sorted(set(git_gate.modified_source_files + git_gate.staged_source_files + git_gate.untracked_source_files + git_gate.manual_review_files)),
        generated_modified_files=git_gate.generated_files,
        path_consistency=consensus.to_dict(),
        generated_exclusion_status="active",
        source_change_status=git_gate.source_change_status,
        gui_import_status="safe" if sentinel.headless_safe else "unsafe",
        pre_uat_verifier_match=consensus.consensus,
        release_verifier_match=consensus.consensus,
        blocking_reasons=blockers,
        recommended_actions=recommended,
        failure_codes=sorted(set(failure_codes)),
        recommended_command=f"{shlex.quote(sys.executable)} -m mac_audit_agent.integrity repair-and-sign --policy {authority.policy} --developer-machine --exclude-generated --migrate-legacy --verify-pre-uat-compatible",
        details={
            "warnings": warnings,
            "git_gate": git_gate.to_dict(),
            "headless_sentinel": sentinel.to_dict(),
            "python_runtime": runtime.to_dict(),
            "hash_scope": scope.to_dict(),
            "artifact_hygiene": hygiene.to_dict(),
            "authority": authority.doctor(),
        },
    )


__all__ = ["IntegrityPreflightResult", "run_integrity_preflight"]

from __future__ import annotations

import inspect
import os
from pathlib import Path

from mac_audit_agent.integrity.artifact_hygiene import scan_artifact_hygiene
from mac_audit_agent.integrity import __main__ as integrity_cli
from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.independent_verify import run_independent_verify
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.trust_states import IntegrityTrustState
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


def run_release_integrity_audit(context: AuditContext) -> list[FunctionalCheck]:
    mode = normalize_policy(os.environ.get("MSAA_RELEASE_POLICY", "dev"))
    paths = integrity_manifest_paths(Path.cwd())
    authority = IntegrityAuthority(Path.cwd(), mode)
    policy_resolution = authority.resolve_policy()
    resolved = IntegrityWrapperAdapter(Path.cwd()).get_integrity_status_for_pre_uat(mode)
    evidence = _authority_summary(resolved) | {"policy_mode": mode, "policy_resolution": policy_resolution.to_dict()}
    checks = [
        FunctionalCheck("integrity.policy_resolved", "Integrity", "policy resolved", "Integrity policy resolves to the canonical authority paths.", "blocker", "integrity"),
        FunctionalCheck("integrity.canonical_manifest_exists", "Integrity", "canonical manifest exists", "Canonical integrity manifest exists for the selected policy.", "blocker", "integrity"),
        FunctionalCheck("integrity.source_signature_valid", "Integrity", "source signature valid", "Canonical manifest signature verifies independently of current source-file hashes.", "blocker", "integrity"),
        FunctionalCheck("integrity.source_files_match_manifest", "Integrity", "source files match manifest", "Protected source matches the cryptographically verified canonical manifest.", "blocker", "integrity"),
        FunctionalCheck("integrity.files_match_manifest", "Integrity", "files match manifest", "Source/package files match the signed canonical manifest.", "blocker", "integrity"),
        FunctionalCheck("integrity.canonical_manifest_signature_valid", "Integrity", "canonical manifest signature valid", "Canonical manifest signature verifies for the selected policy.", "blocker", "integrity"),
        FunctionalCheck("integrity.canonical_files_match_manifest", "Integrity", "canonical files match manifest", "Source/package files match signed canonical manifest.", "blocker", "integrity"),
        FunctionalCheck("integrity.release_artifact_signature_valid", "Integrity", "release artifact signature valid", "Dist artifact signature exists when release mode requires it.", "blocker", "integrity"),
        FunctionalCheck("integrity.release_artifacts_match", "Integrity", "release artifacts match", "Dist artifact hashes match signed artifact manifest.", "blocker", "integrity"),
        FunctionalCheck("integrity.unsigned_source_context", "Integrity", "unsigned source context", "Unsigned source checkout is contextual, not a false release failure.", "medium", "integrity"),
        FunctionalCheck("integrity.release_verification_evidence", "Integrity", "release verification evidence", "Release evidence is present when release mode requires it.", "high", "integrity"),
        FunctionalCheck("integrity.manifest_path_consistency", "Integrity", "manifest path consistency", "Rehash, release verification, Integrity Health, and Pre-UAT resolve the same manifest for the selected policy.", "blocker", "integrity"),
    ]
    output = []
    release_mode = mode == "public_release"
    nonapp_evidence = evidence | {"status": "non_applicable_for_policy", "trust_state": "non_applicable_for_policy", "evidence_status": "non_applicable_for_policy"}
    manifest_missing = resolved.trust_state in {"missing_manifest", "manifest_missing", "manifest_path_divergence"}
    signature_bad = resolved.trust_state in {"signature_missing", "signature_invalid", "manifest_signature_missing", "manifest_signature_invalid", "manifest_modified_after_signing", "unsigned_manifest"}
    mismatch = resolved.trust_state in {IntegrityTrustState.MODIFIED_UNAPPROVED.value, "source_files_modified"}
    output.append(checks[0].passed("Integrity policy resolved through the canonical authority.", {"status": "verified", "policy_resolved": True, "requested_policy": mode, **policy_resolution.to_dict()}))
    output.append(checks[1].failed("Canonical integrity manifest is missing or path-diverged.", "Run integrity repair-and-sign after confirming source trust.", {"manifest_exists": False, **evidence}) if manifest_missing else checks[1].passed("Canonical manifest exists, is readable, and has the source-tree type.", {"status": "verified", "manifest_exists": True, "manifest_path": resolved.manifest_path, "source_type": "source_tree"}))
    exact_failure = f"{resolved.result_code}: {resolved.failure_code or resolved.trust_state}: {resolved.reason}"
    signature_evidence = {"signature_valid": resolved.signature_valid is True, "signature_path": str(policy_resolution.source_signature_path), "result_code": resolved.result_code}
    output.append(checks[2].passed("Canonical source signature verifies for the enrolled signer.", signature_evidence | {"status": "verified"}) if resolved.signature_valid is True else checks[2].failed("Canonical source signature is missing or cryptographically invalid.", "Verify the existing signature and enrolled public key; do not re-sign until source review completes.", signature_evidence))
    file_evidence = {"files_match": not mismatch, "modified_count": len(resolved.modified_files), "missing_count": len(resolved.missing_files), "unexpected_count": len(resolved.extra_files), "modified_sample": resolved.modified_files[:20], "missing_sample": resolved.missing_files[:20], "unexpected_sample": resolved.extra_files[:20], "full_evidence_truncated": True}
    output.append(checks[3].failed(exact_failure, resolved.recommended_action or "Review every protected source difference before authorized signing.", file_evidence) if mismatch else checks[3].passed("Protected source matches the canonical manifest.", file_evidence | {"status": "verified"}))
    output.append(checks[4].failed("Release source manifest is missing in public release mode.", "Generate and sign the public release source manifest.", evidence) if release_mode and manifest_missing else checks[4].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[4].passed("Release source manifest requirement is satisfied for current policy.", evidence | {"status": "verified"}))
    output.append(checks[5].failed("Release source manifest signature is missing or invalid.", "Run public-release-gate to sign and verify release source.", evidence) if release_mode and signature_bad else checks[5].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[5].passed("Release source manifest signature context is valid for current policy.", evidence | {"status": "verified"}))
    output.append(checks[6].failed("Files differ from the signed source manifest.", "Investigate tamper or regenerate a signed release from trusted source.", evidence) if release_mode and mismatch else checks[6].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[6].passed("No signed source file mismatch detected.", evidence | {"status": "verified"}))
    artifact_manifest = Path(policy_resolution.artifact_manifest_path)
    artifact_signature = Path(policy_resolution.artifact_signature_path)
    artifact_evidence = evidence | {"artifact_manifest_path": str(artifact_manifest), "artifact_signature_path": str(artifact_signature)}
    output.append(checks[7].failed("Release artifact signature is missing.", "Run public-release-gate --sign-artifacts after building final artifacts.", artifact_evidence) if release_mode and not artifact_signature.exists() else checks[7].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[7].passed("Release artifact signature file exists for current policy.", artifact_evidence | {"status": "verified"}))
    output.append(checks[8].failed("Release artifact manifest is missing.", "Run public-release-gate --sign-artifacts on the exact upload files.", artifact_evidence) if release_mode and not artifact_manifest.exists() else checks[8].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[8].passed("Release artifact manifest file exists for current policy.", artifact_evidence | {"status": "verified"}))
    if not release_mode and resolved.trust_state in {"manifest_path_divergence", "missing_manifest"}:
        output.append(checks[9].warn("Development source signature context cannot be trusted until the canonical manifest exists.", "Run integrity status --verbose and rebuild the canonical development manifest after verifying source trust.", evidence | {"status": "warning"}))
    else:
        output.append(checks[9].passed("Source signature context is explicit for the selected policy.", {"status": "verified", "policy_mode": mode, "signature_exists": Path(policy_resolution.source_signature_path).exists()}))
    output.append(checks[10].failed("Release verification evidence is missing in public release mode.", "Run public-release-gate and retain generated release evidence.", evidence) if release_mode and not artifact_manifest.exists() else checks[10].skipped("non_applicable_for_policy", "", nonapp_evidence) if not release_mode else checks[10].passed("Release evidence requirement is satisfied for current policy.", evidence | {"status": "verified"}))
    consistency = {
        "policy_mode": mode,
        "authority_manifest_path": str(policy_resolution.source_manifest_path),
        "pre_uat_manifest_path": str(policy_resolution.source_manifest_path),
        "release_verify_manifest_path": resolved.manifest_path,
        "integrity_health_manifest_path": str(policy_resolution.source_manifest_path),
        "legacy_manifest_present": bool(authority.discover_legacy_manifests().discovered_legacy_manifests),
        "canonical_manifest_used": resolved.canonical_manifest_used,
    }
    if not resolved.canonical_manifest_used or resolved.trust_state == "manifest_path_divergence":
        output.append(checks[11].failed("Manifest path divergence detected.", "Run repair-and-sign and verification through the integrity authority.", {"path_consistent": False, "trust_state": resolved.trust_state, **consistency}))
    else:
        output.append(checks[11].passed("Manifest path resolver is consistent for selected policy.", consistency | {"status": "verified", "path_consistent": True}))
    output.extend(_run_developer_machine_checks(paths, resolved, mode))
    output.extend(_run_hardening_checks(resolved, mode))
    return output


def _run_hardening_checks(resolved, mode: str) -> list[FunctionalCheck]:
    checks = [
        FunctionalCheck("integrity.preflight_passed", "Integrity", "preflight passed", "Integrity preflight passes or reports exact blockers.", "blocker", "integrity"),
        FunctionalCheck("integrity.hash_scope_classified", "Integrity", "hash scope classified", "Hash scope has no dangerous unclassified source files.", "high", "integrity"),
        FunctionalCheck("integrity.independent_verify_matches", "Integrity", "independent verify matches", "Independent verifier matches same-process verification.", "blocker", "integrity"),
        FunctionalCheck("integrity.artifact_hygiene", "Integrity", "artifact hygiene", "Runtime/private artifacts are absent from source and dist release scope.", "blocker", "integrity"),
    ]
    preflight = run_integrity_preflight(mode, root=Path.cwd(), strict=True, approve_current_source=True)
    scope = build_hash_scope_report(Path.cwd(), policy=mode)
    independent = run_independent_verify(mode, root=Path.cwd(), authority_status=resolved.status)
    hygiene = scan_artifact_hygiene(Path.cwd(), include_dist=False)
    results: list[FunctionalCheck] = []
    preflight_evidence = {key: value for key, value in preflight.to_dict().items() if key != "details"}
    results.append(checks[0].passed("Integrity preflight passed.", preflight_evidence | {"status": "verified"}) if preflight.status == "pass" else checks[0].failed("; ".join(preflight.blocking_reasons), "; ".join(preflight.recommended_actions), preflight_evidence))
    scope_evidence = {"included_count": len(scope.included_files), "excluded_count": len(scope.excluded_files), "generated_count": len(scope.generated_files), "runtime_count": len(scope.runtime_files), "build_count": len(scope.build_files), "unknown_count": len(scope.dangerous_unclassified_files), "unknown_sample": scope.dangerous_unclassified_files[:20], "full_file_lists_truncated": True}
    results.append(checks[1].passed("All source-scope files are classified.", scope_evidence | {"status": "verified"}) if not scope.dangerous_unclassified_files else checks[1].failed("Unclassified source-scope files exist.", "Classify or exclude the listed files.", scope_evidence))
    independent_evidence = independent.to_dict()
    independent_evidence["mismatches"] = independent.mismatches[:30]
    independent_evidence["mismatch_count"] = len(independent.mismatches)
    independent_evidence["output_truncated"] = len(independent.mismatches) > 30
    if not independent.mismatch_with_authority and independent.result_code != "INTERNAL_ERROR":
        results.append(checks[2].passed("Independent verifier agrees with the authority result.", independent_evidence | {"status": "verified", "verifier_consistency": True}))
    else:
        results.append(checks[2].failed("Independent verifier disagrees with the authority or encountered an implementation error.", "Inspect independent verifier output and correct the verifier before signing.", independent_evidence | {"verifier_consistency": False}))
    hygiene_payload = hygiene.to_dict()
    for key, value in list(hygiene_payload.items()):
        if isinstance(value, list) and len(value) > 30:
            hygiene_payload[key] = value[:30]
            hygiene_payload[f"{key}_count"] = len(value)
            hygiene_payload[f"{key}_truncated"] = True
    results.append(checks[3].passed("Artifact hygiene passed.", hygiene_payload | {"status": "verified"}) if hygiene.status == "passed" else checks[3].failed("Artifact hygiene failed.", "Remove runtime/private artifacts before release.", hygiene_payload))
    return results


def _run_developer_machine_checks(paths, resolved, mode: str) -> list[FunctionalCheck]:
    checks = [
        FunctionalCheck("integrity.developer_machine_identity_exists", "Integrity", "developer-machine identity exists", "Trusted developer-machine registry exists and loads.", "blocker", "integrity"),
        FunctionalCheck("integrity.developer_machine_signature_valid", "Integrity", "developer-machine signature valid", "Canonical manifest signature verifies against an enrolled developer-machine public key.", "blocker", "integrity"),
        FunctionalCheck("integrity.signing_machine_authorized", "Integrity", "signing machine authorized", "Signing is limited to an enrolled developer machine; verification can occur elsewhere.", "blocker", "integrity"),
        FunctionalCheck("integrity.no_unknown_status", "Integrity", "no unknown status", "Integrity status resolver returns a classified trust state.", "blocker", "integrity"),
        FunctionalCheck("integrity.no_pass_with_failed_evidence", "Integrity", "no pass with failed evidence", "Integrity checks do not pass while evidence.status is failed.", "blocker", "integrity"),
        FunctionalCheck("integrity.generated_artifacts_excluded", "Integrity", "generated artifacts excluded", "Generated docs, egg-info, temp sqlite, and caches do not cause manifest mismatches.", "high", "integrity"),
        FunctionalCheck("integrity.integrity_cli_headless_safe", "Integrity", "integrity CLI headless safe", "Integrity CLI path does not import Qt/PySide/AppKit or create QApplication.", "blocker", "integrity"),
    ]
    results: list[FunctionalCheck] = []
    registry = load_trusted_developer_machines(Path.cwd())
    active = registry.active_machines()
    evidence = _authority_summary(resolved) | {"policy_mode": mode, "trusted_developer_machine_registry": str(paths.canonical_trusted_developer_machines)}
    pass_evidence = evidence | {"status": "verified"}
    if active:
        results.append(checks[0].passed("Trusted developer-machine registry contains an active identity.", pass_evidence | {"active_machine_count": len(active), "identity_exists": True}))
    else:
        results.append(checks[0].failed("No active trusted developer-machine identity is enrolled.", "Run integrity machine enroll before signing a trusted manifest.", evidence))

    if resolved.signature_valid is True:
        results.append(checks[1].passed("Developer-machine signature validates against the enrolled public key.", pass_evidence | {"signature_valid": True}))
    else:
        results.append(checks[1].failed("Developer-machine signature is missing or invalid.", "Run integrity sign --developer-machine after enrolling this Mac.", evidence))

    if resolved.trust_state in {"trusted_developer_machine_signed_manifest", "machine_fingerprint_mismatch"} or active:
        results.append(checks[2].passed("Signing authorization is represented by developer-machine enrollment state.", pass_evidence | {"signer_authorized": True}))
    else:
        results.append(checks[2].failed("Signing machine authorization is not established.", "Enroll this Mac or verify using a signed manifest from an enrolled developer machine.", evidence))

    if resolved.trust_state and "unknown" not in resolved.trust_state:
        results.append(checks[3].passed("Integrity status is classified.", pass_evidence | {"trust_state": resolved.trust_state}))
    else:
        results.append(checks[3].failed("Integrity status is unknown.", "Map the condition to a concrete trust state.", evidence))

    if resolved.status == "verified" and resolved.details.get("manifest_verification", {}).get("ok") is False:
        results.append(checks[4].failed("Integrity status passed while manifest evidence failed.", "Do not pass checks with failed evidence.", evidence))
    else:
        results.append(checks[4].passed("No PASS result carries failed manifest evidence.", pass_evidence))

    generated_false_positive = any(path.endswith(".egg-info/PKG-INFO") or "PRE_UAT_" in path or path.endswith(".sqlite3") for path in resolved.modified_files + resolved.extra_files)
    if generated_false_positive:
        results.append(checks[5].failed("Generated artifacts are still included in integrity mismatches.", "Update integrity exclusions for generated outputs.", evidence))
    else:
        results.append(checks[5].passed("Generated artifact paths are excluded from source integrity mismatches.", pass_evidence))

    source = inspect.getsource(integrity_cli)
    forbidden = [name for name in ("PySide6", "QApplication", "AppKit") if name in source]
    if forbidden:
        results.append(checks[6].failed("Integrity CLI imports GUI modules.", "Remove Qt/AppKit imports from integrity commands.", evidence | {"forbidden": forbidden}))
    else:
        from mac_audit_agent.integrity.headless_sentinel import isolated_integrity_import_check
        isolated = isolated_integrity_import_check()
        if isolated.headless_safe:
            results.append(checks[6].passed("Integrity CLI is headless-safe in a fresh subprocess.", {"status": "verified", "headless_safe": True, "new_gui_modules": []}))
        else:
            results.append(checks[6].failed("Integrity CLI imported GUI modules in a fresh subprocess.", "Remove the reported GUI import chain from the integrity entry point.", {"headless_safe": False, "new_gui_modules": isolated.imported_gui_modules}))
    return results


def _authority_summary(resolved) -> dict[str, object]:
    return {
        "status": resolved.status,
        "trust_state": resolved.trust_state,
        "result_code": resolved.result_code,
        "failure_code": resolved.failure_code,
        "manifest_path": resolved.manifest_path,
        "signature_valid": resolved.signature_valid,
        "canonical_manifest_used": resolved.canonical_manifest_used,
        "modified_count": len(resolved.modified_files),
        "missing_count": len(resolved.missing_files),
        "unexpected_count": len(resolved.extra_files),
    }


__all__ = ["run_release_integrity_audit"]

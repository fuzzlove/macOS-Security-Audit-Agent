from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.hash_verifier import verify_manifest_two_pass
from mac_audit_agent.integrity.independent_verify import run_independent_verify
from mac_audit_agent.integrity.pre_uat_compat import verify_pre_uat_integrity_compatibility
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.signature_roundtrip import validate_signature_roundtrip
from mac_audit_agent.integrity.ui_compat import verify_integrity_health_model_matches_cli


@dataclass(slots=True)
class HardenValidateResult:
    status: str
    trust_state: str
    pre_uat_compatible: bool
    independent_verify: str
    tamper_self_test: str
    headless_safe: bool
    release_ready_integrity_gate: str
    evidence_dir: str
    blocking_reasons: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def harden_and_validate(
    root: Path,
    *,
    policy: str,
    author: str,
    reason: str,
    build_id: str = "",
    developer_machine: bool = False,
    exclude_generated: bool = True,
    migrate_legacy: bool = True,
    verify_pre_uat_compatible: bool = True,
    approve_current_source: bool = False,
    typed_confirmation: str = "",
    run_independent: bool = False,
    run_tamper_self_test: bool = False,
) -> HardenValidateResult:
    root = Path(root).resolve(strict=False)
    evidence_dir = _evidence_dir()
    preflight = run_integrity_preflight(policy, root=root, strict=True, approve_current_source=approve_current_source)
    _write_stage(evidence_dir, "preflight", preflight.to_dict())
    if preflight.status != "verified":
        return _result("failed", "preflight_failed", False, "not_run", "not_run", preflight.gui_import_status == "safe", "fail", evidence_dir, preflight.blocking_reasons, {"preflight": preflight.to_dict()})

    authority = IntegrityAuthority(root, policy)
    manifest_path = Path(authority.resolve_paths().source_manifest_path)
    signature_path = Path(authority.resolve_paths().source_signature_path)
    if manifest_path.exists():
        shutil.copy2(manifest_path, evidence_dir / "manifest_before.json")
    repair = repair_and_sign_integrity(
        root,
        policy=policy,
        author=author,
        reason=reason,
        build_id=build_id,
        developer_machine=developer_machine,
        verify_pre_uat_compatible=verify_pre_uat_compatible,
        migrate_legacy=migrate_legacy,
        exclude_generated=exclude_generated,
        approve_current_source=approve_current_source,
        typed_confirmation=typed_confirmation,
    )
    _write_stage(evidence_dir, "repair_and_sign", repair.to_dict())
    if manifest_path.exists():
        shutil.copy2(manifest_path, evidence_dir / "manifest_after.json")
    if signature_path.exists():
        shutil.copy2(signature_path, evidence_dir / "signature_after.json")

    final = authority.status()
    two_pass = verify_manifest_two_pass(root, manifest_path)
    roundtrip = validate_signature_roundtrip(root, manifest_path, signature_path)
    pre_uat = verify_pre_uat_integrity_compatibility(policy, root=root)
    ui = verify_integrity_health_model_matches_cli(policy, root=root)
    independent = run_independent_verify(policy, root=root, authority_status=final.status) if run_independent else None
    _write_stage(evidence_dir, "path_consensus", preflight.path_consistency)
    _write_stage(evidence_dir, "git_gate", preflight.details.get("git_gate", {}))
    _write_stage(evidence_dir, "signature_roundtrip", roundtrip.to_dict())
    _write_stage(evidence_dir, "pre_uat_compat", pre_uat.to_dict())
    _write_stage(evidence_dir, "ui_compat", ui)
    _write_stage(evidence_dir, "independent_verify", independent.to_dict() if independent else {"status": "skipped"})
    _write_stage(evidence_dir, "final_status", final.to_dict())
    blockers: list[str] = []
    if final.status != "verified":
        blockers.append(final.trust_state)
    if two_pass.status != "verified":
        blockers.append(two_pass.failure_stage)
    if roundtrip.status != "verified":
        blockers.append("signature_roundtrip_failed")
    if not pre_uat.compatible:
        blockers.extend(pre_uat.pre_uat_blockers)
    if ui.get("status") != "verified":
        blockers.append("integrity_health_model_mismatch")
    if independent and independent.independent_status != "verified":
        blockers.append("independent_verify_failed")
    status = "verified" if not blockers else "failed"
    result = _result(
        status,
        final.trust_state,
        pre_uat.compatible,
        independent.independent_status if independent else "skipped",
        roundtrip.status if run_tamper_self_test else "skipped",
        preflight.gui_import_status == "safe",
        "pass" if not blockers else "fail",
        evidence_dir,
        blockers,
        {"repair_and_sign": repair.to_dict(), "two_pass": two_pass.to_dict(), "roundtrip": roundtrip.to_dict(), "pre_uat": pre_uat.to_dict(), "ui": ui, "independent": independent.to_dict() if independent else {}},
    )
    _write_stage(evidence_dir, "harden_and_validate", result.to_dict())
    return result


def _result(status: str, trust_state: str, pre_uat: bool, independent: str, tamper: str, headless: bool, release_gate: str, evidence_dir: Path, blockers: list[str], details: dict[str, object]) -> HardenValidateResult:
    return HardenValidateResult(status, trust_state, pre_uat, independent, tamper, headless, release_gate, str(evidence_dir), blockers, details)


def _evidence_dir() -> Path:
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    path = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity" / "repair_evidence" / stamp
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_stage(directory: Path, name: str, payload: object) -> None:
    (directory / f"{name}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


__all__ = ["HardenValidateResult", "harden_and_validate"]

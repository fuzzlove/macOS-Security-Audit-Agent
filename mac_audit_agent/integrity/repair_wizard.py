from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.core import IntegrityEngine
from mac_audit_agent.integrity.diff_report import IntegrityDiffReport, IntegrityState
from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.models import utc_now_iso


@dataclass
class RepairStep:
    step_id: str
    title: str
    description: str
    actions: list[str] = field(default_factory=list)
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RepairPlan:
    state: str
    steps: list[RepairStep]
    safe_actions: list[str] = field(default_factory=list)
    dangerous_actions: list[str] = field(default_factory=list)
    recommended_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "steps": [item.to_dict() for item in self.steps],
            "safe_actions": list(self.safe_actions),
            "dangerous_actions": list(self.dangerous_actions),
            "recommended_action": self.recommended_action,
        }


@dataclass
class RepairResult:
    started_at: str
    completed_at: str = ""
    success: bool = False
    actions_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RepairWizard:
    def __init__(self, engine: IntegrityEngine, *, repair_source_dir: Path | None = None, log_path: Path | None = None) -> None:
        self.engine = engine
        self.repair_source_dir = Path(repair_source_dir).expanduser() if repair_source_dir else None
        self.log_path = log_path or (Path.home() / "Library" / "Logs" / "MacAuditAgent" / "integrity.log")

    def build_plan(self, report: IntegrityDiffReport | None = None) -> RepairPlan:
        report = report or self.engine.generate_diff_report()
        explain = RepairStep("explain_issue", "Explain Issue", report.explanation, [report.summary])
        if report.state == IntegrityState.VERIFIED:
            choose = RepairStep("choose_action", "Choose Action", "No repair is needed.", ["No repair needed"])
            return RepairPlan(report.state.value, [explain, choose], recommended_action="No repair needed.")
        if report.state == IntegrityState.STALE_MANIFEST:
            choose = RepairStep(
                "choose_action",
                "Choose Action",
                "The manifest appears stale. Update the trusted baseline only after verifying the update.",
                ["Update Trusted Baseline (after verifying update)", "Export Evidence Snapshot first"],
                requires_confirmation=True,
            )
            return RepairPlan(report.state.value, [explain, choose], dangerous_actions=["replace_trusted_manifest"], recommended_action="Verify update provenance, then create trusted baseline.")
        if report.state == IntegrityState.UNKNOWN:
            choose = RepairStep(
                "choose_action",
                "Choose Action",
                "No trusted manifest exists.",
                ["Create Trusted Baseline (only if trusted install)", "Reinstall MSAA from trusted source"],
                requires_confirmation=True,
            )
            return RepairPlan(report.state.value, [explain, choose], dangerous_actions=["create_trusted_baseline"], recommended_action="Create a baseline only after trusted-source confirmation.")
        if report.state in {IntegrityState.MODIFIED, IntegrityState.MISSING_FILES, IntegrityState.EXTRA_FILES, IntegrityState.FAILED, IntegrityState.DRAFT}:
            actions = ["Export Evidence Snapshot first", "Repair Installation (recommended)", "Reinstall MSAA from trusted source"]
            safe = ["repair_missing_components", "repair_runtime_structure", "repair_user_safe_permissions"]
            dangerous = ["overwrite_application_directory", "replace_trusted_manifest", "reinstall_system_daemon"]
            choose = RepairStep("choose_action", "Choose Action", "Application integrity requires guided recovery.", actions, requires_confirmation=True)
            verify = RepairStep("verify_after_repair", "Verification After Repair", "Re-run integrity check and compare before/after.", ["Run Integrity Check"])
            return RepairPlan(report.state.value, [explain, choose, verify], safe_actions=safe, dangerous_actions=dangerous, recommended_action="Export evidence and repair from trusted source.")
        return RepairPlan(report.state.value, [explain], recommended_action="Review diagnostics.")

    def safe_repair(self, *, confirmation: str = "", allow_manifest_replace: bool = False) -> RepairResult:
        before_report = self.engine.generate_diff_report()
        result = RepairResult(started_at=utc_now_iso(), before=before_report.to_dict())
        self._log("repair_started", {"state": before_report.state.value})
        try:
            if before_report.state == IntegrityState.VERIFIED:
                result.success = True
                result.actions_run.append("no_repair_needed")
            if before_report.missing_files and self.repair_source_dir:
                self._restore_missing_files(before_report, result)
            if before_report.state in {IntegrityState.STALE_MANIFEST, IntegrityState.UNKNOWN} and allow_manifest_replace:
                if confirmation != "I TRUST THIS INSTALLATION":
                    result.errors.append("Trusted baseline replacement requires confirmation: I TRUST THIS INSTALLATION")
                else:
                    self.create_trusted_baseline(confirmation=confirmation)
                    result.actions_run.append("trusted_baseline_created")
            after_report = self.engine.generate_diff_report()
            result.after = after_report.to_dict()
            result.success = after_report.state in {IntegrityState.VERIFIED, IntegrityState.STALE_MANIFEST} and not result.errors
        except Exception as exc:
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.completed_at = utc_now_iso()
        self._log("repair_completed", result.to_dict())
        return result

    def create_trusted_baseline(self, *, confirmation: str) -> Path:
        if confirmation != "I TRUST THIS INSTALLATION":
            raise PermissionError("Trusted baseline creation requires explicit user confirmation.")
        manifest_path = self.engine.manifest_path or (self.engine.root / "msaa_integrity_manifest.json")
        backup_path = None
        if manifest_path.exists():
            backup_path = manifest_path.with_suffix(f".{utc_now_iso().replace(':', '').replace('.', '')}.bak")
            backup_path.write_text(manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
        manifest = create_integrity_manifest(self.engine.root, source_type="source_tree", trust_state="trusted", notes="Created by Integrity Repair Wizard after explicit trusted-install confirmation.")
        path = write_integrity_manifest(manifest, manifest_path)
        self._log("baseline_created", {"manifest_path": str(path), "backup_path": str(backup_path or ""), "entries": len(manifest.file_entries)})
        return path

    def _restore_missing_files(self, report: IntegrityDiffReport, result: RepairResult) -> None:
        assert self.repair_source_dir is not None
        for change in report.missing_files:
            source = self.repair_source_dir / change.file_path
            destination = self.engine.root / change.file_path
            if not source.is_file():
                result.errors.append(f"Trusted repair source missing file: {change.file_path}")
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            result.actions_run.append(f"restored:{change.file_path}")

    def _log(self, action: str, payload: dict[str, Any]) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"timestamp": utc_now_iso(), "action": action, **payload}, sort_keys=True) + "\n")
        except Exception:
            pass

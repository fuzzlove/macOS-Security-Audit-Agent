from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import ScanResult, utc_now_iso
from mac_audit_agent.reporting import execution_evidence_from_scan
from mac_audit_agent.storage import AuditDatabase, json_safe


LOGGER = logging.getLogger(__name__)


def default_recovery_snapshot_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "snapshots"


def format_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} TB"


@dataclass
class CleanupCandidate:
    category: str
    kind: str
    path: str
    current_bytes: int = 0
    baseline_bytes: int = 0
    recoverable_bytes: int = 0
    recommendation: str = ""
    risk: str = "low"
    protected: bool = False
    last_modified: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return json_safe(self.__dict__)


@dataclass
class CleanupPreview:
    generated_at: str
    candidates: list[CleanupCandidate] = field(default_factory=list)
    protected_paths: list[str] = field(default_factory=list)
    total_recoverable_bytes: int = 0
    opportunities: int = 0
    risk_level: str = "safe"
    performance_improvement: str = "Low"
    recovery_score: int = 100
    summary: str = ""
    growth_summary: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = json_safe(self.__dict__)
        payload["candidates"] = [item.to_dict() for item in self.candidates]
        return payload


@dataclass
class IncidentAwarenessAssessment:
    generated_at: str
    level: str
    title: str
    reasons: list[str] = field(default_factory=list)
    unresolved_counts: dict[str, int] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return json_safe(self.__dict__)


class SystemRecoveryCenter:
    def __init__(self, db: AuditDatabase, config: AuditConfig) -> None:
        self.db = db
        self.config = config

    def _as_dict(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if hasattr(value, "to_dict"):
            try:
                converted = value.to_dict()
            except Exception:
                converted = {}
            if isinstance(converted, dict):
                return converted
        if hasattr(value, "__dict__"):
            data = getattr(value, "__dict__", {})
            if isinstance(data, dict):
                return dict(data)
        return {}

    def protected_roots(self) -> list[Path]:
        home = Path.home()
        roots = [
            home / "Library" / "Application Support" / "MacAuditAgent",
            home / "Library" / "Application Support" / "MacAuditAgent" / "snapshots",
            home / "Library" / "Logs" / "MacAuditAgent",
            home / ".mac_audit_agent",
            Path(self.db.path).resolve(),
        ]
        for path in getattr(self.config, "recovery_cleanup_exclusions", []) or []:
            try:
                roots.append(Path(path).expanduser())
            except Exception:
                continue
        return [root.expanduser() for root in roots]

    def _normalize_path(self, path: Path | str) -> Path:
        return Path(path).expanduser()

    def _safe_resolve(self, path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path.absolute()

    def _is_protected(self, path: Path) -> bool:
        candidate = self._safe_resolve(path)
        for root in self.protected_roots():
            resolved = self._safe_resolve(root)
            if candidate == resolved or resolved in candidate.parents:
                return True
        return False

    def _dir_size(self, path: Path, *, deadline: float | None = None) -> int:
        if not path.exists():
            return 0
        if path.is_file():
            try:
                return path.stat().st_size
            except OSError:
                return 0
        total = 0
        for root, _dirs, files in os.walk(path):
            if deadline is not None and datetime.now(timezone.utc).timestamp() >= deadline:
                break
            for name in files:
                if deadline is not None and datetime.now(timezone.utc).timestamp() >= deadline:
                    break
                child = Path(root) / name
                try:
                    total += child.stat().st_size
                except OSError:
                    continue
        return total

    def _dir_mtime(self, path: Path) -> str:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            return ""

    def _baseline_map(self) -> dict[str, dict[str, Any]]:
        baselines = {}
        for row in self.db.list_system_recovery_baselines(limit=500):
            baselines[str(row.get("baseline_key", ""))] = row
        return baselines

    def _baseline_key(self, category: str, path: Path) -> str:
        return hashlib.sha256(f"{category}:{self._safe_resolve(path)}".encode("utf-8")).hexdigest()[:20]

    def _default_cleanup_specs(self) -> list[dict[str, Any]]:
        home = Path.home()
        temp_dir = Path(tempfile.gettempdir())
        return [
            {"category": "safe", "kind": "application cache", "path": home / "Library" / "Caches", "risk": "low"},
            {"category": "safe", "kind": "browser cache", "path": home / "Library" / "Caches" / "com.apple.Safari", "risk": "low"},
            {"category": "safe", "kind": "browser cache", "path": home / "Library" / "Caches" / "Google" / "Chrome", "risk": "low"},
            {"category": "safe", "kind": "browser cache", "path": home / "Library" / "Caches" / "Firefox", "risk": "low"},
            {"category": "safe", "kind": "thumbnail cache", "path": home / "Library" / "Caches" / "com.apple.QuickLook.thumbnailcache", "risk": "low"},
            {"category": "safe", "kind": "temporary files", "path": temp_dir, "risk": "low"},
            {"category": "review", "kind": "crash logs", "path": home / "Library" / "Logs" / "DiagnosticReports", "risk": "medium"},
            {"category": "review", "kind": "browser session data", "path": home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Sessions", "risk": "medium"},
            {"category": "review", "kind": "browser session data", "path": home / "Library" / "Application Support" / "Safari", "risk": "medium"},
            {"category": "review", "kind": "browser session data", "path": home / "Library" / "Application Support" / "Firefox", "risk": "medium"},
        ]

    def _is_recent(self, path: Path, max_age_days: int) -> bool:
        if not path.exists():
            return False
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return False
        return datetime.now(timezone.utc) - mtime <= timedelta(days=max_age_days)

    def incident_awareness_check(self, current_scan_result: ScanResult | None = None, current_payload: dict[str, Any] | None = None) -> IncidentAwarenessAssessment:
        scan_result = current_scan_result or self.db.latest_scan_result()
        payload = current_payload or (scan_result.to_dict().get("collected_artifacts", {}) if scan_result else {})
        findings = list(scan_result.findings) if scan_result else []
        review_statuses = self.db.get_review_statuses(scan_result.scan_id) if scan_result else {}
        unresolved = 0
        for finding in findings:
            status = review_statuses.get(("finding", finding.id))
            if finding.severity in {"critical", "high"} and (not status or status.review_state not in {"reviewed", "false positive", "resolved"}):
                unresolved += 1
        events = self.db.recent_background_monitor_events(limit=200)
        event_types = [str(event.event_type) for event in events]
        recent_event_set = set(event_types)
        reasons: list[str] = []
        if unresolved:
            reasons.append(f"{unresolved} unresolved high/critical findings remain open.")
        if "alert_storm_detected" in recent_event_set:
            reasons.append("An alert storm was detected recently.")
        if recent_event_set.intersection({"launchdaemon_added", "launchagent_added", "persistence_item_created_high_risk"}):
            reasons.append("Recent persistence changes were observed.")
        if "new_admin_user_detected" in recent_event_set:
            reasons.append("A recent admin change was observed.")
        if recent_event_set.intersection({"suspicious_process_observed", "capture_process_observed", "capture_capable_process_observed"}):
            reasons.append("Recent execution evidence was observed.")
        if recent_event_set.intersection({"network_ip_assigned", "vpn_connected", "localhost_hidden_port_detected"}):
            reasons.append("Recent unexplained network activity was observed.")
        forecast = self.db.latest_apple_security_forecast() or {}
        forecast_level = str(forecast.get("level", "")).lower()
        if forecast_level == "urgent":
            reasons.append("Apple Exposure Assessment is urgent.")
        processes = payload.get("processes", {}).get("all", []) if isinstance(payload.get("processes"), dict) else []
        low_trust = 0
        for item in processes:
            item_data = self._as_dict(item)
            try:
                trust_score = int(float(item_data.get("trust_score", 0)))
            except (TypeError, ValueError):
                continue
            if trust_score and trust_score < 70:
                low_trust += 1
        if low_trust:
            reasons.append(f"{low_trust} low-trust processes were found.")
        execution_evidence = execution_evidence_from_scan(scan_result) if scan_result else []
        if execution_evidence:
            reasons.append(f"{len(execution_evidence)} execution evidence items were generated.")
        if "alert storm" in " ".join(reasons).lower() or unresolved >= 2:
            level = "incident_response_recommended"
        elif unresolved or recent_event_set.intersection({"launchdaemon_added", "launchagent_added", "persistence_item_created_high_risk", "new_admin_user_detected"}) or execution_evidence or forecast_level == "urgent" or recent_event_set.intersection({"network_ip_assigned", "vpn_connected", "localhost_hidden_port_detected"}):
            level = "investigate_first"
        elif low_trust or recent_event_set.intersection({"persistence_item_created"}):
            level = "caution"
        else:
            level = "safe"
        title_map = {
            "safe": "Safe",
            "caution": "Caution",
            "investigate_first": "Investigate First",
            "incident_response_recommended": "Incident Response Recommended",
        }
        recommendation_map = {
            "safe": "Proceed with whitelist-only cleanup if desired.",
            "caution": "Review cleanup candidates before deleting anything.",
            "investigate_first": "Review recent changes and preserve evidence before cleanup.",
            "incident_response_recommended": "Preserve evidence and review before deleting caches or logs.",
        }
        return IncidentAwarenessAssessment(
            generated_at=utc_now_iso(),
            level=level,
            title=title_map[level],
            reasons=reasons or ["No recent incident indicators were found."],
            unresolved_counts={"high_or_critical_findings": unresolved, "low_trust_processes": low_trust},
            recommendation=recommendation_map[level],
        )

    def _candidate_score(self, candidate: CleanupCandidate) -> int:
        score = int(candidate.current_bytes / (1024 * 1024))
        if candidate.category == "review":
            score += 10
        if candidate.baseline_bytes and candidate.current_bytes > candidate.baseline_bytes:
            score += min(25, int((candidate.current_bytes - candidate.baseline_bytes) / (1024 * 1024 * 50)))
        return score

    def _recommendation_for_candidate(self, candidate: CleanupCandidate, baseline: dict[str, Any] | None) -> str:
        if candidate.protected:
            return "Protected artifact - never clean automatically."
        if not candidate.current_bytes:
            return "No action needed."
        if not baseline or not int(baseline.get("baseline_bytes", 0) or 0):
            return "Baseline recorded; re-run to compare growth."
        baseline_bytes = int(baseline.get("baseline_bytes", 0) or 0)
        if candidate.current_bytes >= int(baseline_bytes * 1.25) and candidate.current_bytes - baseline_bytes >= 50 * 1024 * 1024:
            return "Cleanup candidate."
        if candidate.current_bytes >= 1024 * 1024 * 1024 and candidate.category == "safe":
            return "Cleanup candidate."
        return "No action needed."

    def _scan_candidate(self, spec: dict[str, Any], deadline: float | None = None) -> list[CleanupCandidate]:
        path = self._normalize_path(spec["path"])
        if self._is_protected(path):
            return []
        if not path.exists():
            return []
        candidates: list[CleanupCandidate] = []
        baseline_map = self._baseline_map()
        category = str(spec.get("category", "safe"))
        kind = str(spec.get("kind", "cleanup"))
        risk = str(spec.get("risk", "low"))
        max_age_days = int(self.config.cleanup_crash_log_age_days if kind == "crash logs" else 30)
        if path.is_file():
            current = self._dir_size(path, deadline=deadline)
            if current:
                key = self._baseline_key(category, path)
                baseline = baseline_map.get(key)
                candidate = CleanupCandidate(
                    category=category,
                    kind=kind,
                    path=str(path),
                    current_bytes=current,
                    baseline_bytes=int(baseline.get("baseline_bytes", 0) if baseline else 0),
                    recoverable_bytes=current,
                    risk=risk,
                    protected=False,
                    last_modified=self._dir_mtime(path),
                )
                candidate.recommendation = self._recommendation_for_candidate(candidate, baseline)
                candidates.append(candidate)
            return candidates
        entries: list[Path] = []
        try:
            entries = [item for item in path.iterdir() if not item.name.startswith(".")]
        except OSError:
            return []
        scored: list[tuple[int, Path]] = []
        for entry in entries:
            if deadline is not None and datetime.now(timezone.utc).timestamp() >= deadline:
                break
            if self._is_protected(entry):
                continue
            if kind == "crash logs" and not self._is_recent(entry, max_age_days):
                continue
            size = self._dir_size(entry, deadline=deadline)
            if size <= 0:
                continue
            if size < 5 * 1024 * 1024 and kind not in {"crash logs", "browser session data"}:
                continue
            scored.append((size, entry))
        scored.sort(key=lambda item: item[0], reverse=True)
        for size, entry in scored[:12]:
            key = self._baseline_key(category, entry)
            baseline = baseline_map.get(key)
            candidate = CleanupCandidate(
                category=category,
                kind=kind,
                path=str(entry),
                current_bytes=size,
                baseline_bytes=int(baseline.get("baseline_bytes", 0) if baseline else 0),
                recoverable_bytes=size,
                risk=risk,
                protected=False,
                last_modified=self._dir_mtime(entry),
            )
            candidate.recommendation = self._recommendation_for_candidate(candidate, baseline)
            candidates.append(candidate)
        return candidates

    def build_cleanup_preview(
        self,
        current_scan_result: ScanResult | None = None,
        current_payload: dict[str, Any] | None = None,
        extra_roots: list[dict[str, Any]] | None = None,
    ) -> CleanupPreview:
        specs = self._default_cleanup_specs()
        if extra_roots:
            specs.extend(extra_roots)
        deadline = datetime.now(timezone.utc).timestamp() + max(2, int(getattr(self.config, "recovery_scan_timeout_seconds", 10) or 10))
        candidates: list[CleanupCandidate] = []
        for spec in specs:
            if datetime.now(timezone.utc).timestamp() >= deadline:
                break
            candidates.extend(self._scan_candidate(spec, deadline=deadline))
        baseline_map = self._baseline_map()
        protected_paths = [str(path) for path in self.protected_roots()]
        total_recoverable = sum(item.recoverable_bytes for item in candidates if item.recommendation != "No action needed." and not item.protected)
        opportunities = sum(1 for item in candidates if "candidate" in item.recommendation.lower())
        growth_summary: list[dict[str, Any]] = []
        for candidate in candidates:
            if candidate.baseline_bytes and candidate.current_bytes > candidate.baseline_bytes:
                growth_summary.append(
                    {
                        "path": candidate.path,
                        "category": candidate.category,
                        "baseline_bytes": candidate.baseline_bytes,
                        "current_bytes": candidate.current_bytes,
                        "growth_bytes": candidate.current_bytes - candidate.baseline_bytes,
                    }
                )
        disk = shutil.disk_usage(Path.home())
        free_ratio = disk.free / disk.total if disk.total else 0.0
        startup_impact = 0
        payload = current_payload or (current_scan_result.to_dict().get("collected_artifacts", {}) if current_scan_result else {})
        if isinstance(payload.get("launch_snapshots"), list):
            startup_impact += len(payload.get("launch_snapshots", []))
        if isinstance(payload.get("users"), list):
            startup_impact += len(payload.get("users", []))
        if isinstance(payload.get("processes"), dict):
            startup_impact += len(payload.get("processes", {}).get("all", []))
        score = 100
        score -= min(35, int((total_recoverable / (1024 * 1024 * 1024)) * 4))
        score -= min(15, int((1.0 - free_ratio) * 100))
        score -= min(15, startup_impact)
        score -= min(10, opportunities * 2)
        score = max(0, min(100, score))
        if total_recoverable >= 10 * 1024 * 1024 * 1024:
            improvement = "High"
        elif total_recoverable >= 2 * 1024 * 1024 * 1024:
            improvement = "Medium"
        elif total_recoverable >= 100 * 1024 * 1024:
            improvement = "Low"
        else:
            improvement = "Low"
        risk_level = "safe"
        if any(item.risk == "medium" for item in candidates):
            risk_level = "caution"
        if any(item.risk == "high" for item in candidates):
            risk_level = "investigate_first"
        summary = f"Potential space recovery: {format_bytes(total_recoverable)}."
        preview = CleanupPreview(
            generated_at=utc_now_iso(),
            candidates=sorted(candidates, key=self._candidate_score, reverse=True),
            protected_paths=protected_paths,
            total_recoverable_bytes=total_recoverable,
            opportunities=opportunities,
            risk_level=risk_level,
            performance_improvement=improvement,
            recovery_score=score,
            summary=summary,
            growth_summary=growth_summary,
        )
        for candidate in preview.candidates:
            key = self._baseline_key(candidate.category, Path(candidate.path))
            if key not in baseline_map:
                self.db.record_system_recovery_baseline(
                    {
                        "baseline_key": key,
                        "category": candidate.category,
                        "path": candidate.path,
                        "baseline_bytes": candidate.current_bytes,
                        "observed_at": preview.generated_at,
                        "current_bytes": candidate.current_bytes,
                        "kind": candidate.kind,
                        "risk": candidate.risk,
                    }
                )
        return preview

    def create_evidence_snapshot(
        self,
        current_scan_result: ScanResult | None = None,
        current_payload: dict[str, Any] | None = None,
        assessment: IncidentAwarenessAssessment | None = None,
        preview: CleanupPreview | None = None,
        reason: str = "cleanup",
    ) -> dict[str, Any]:
        snapshot_dir = self.config.recovery_snapshot_dir if getattr(self.config, "recovery_snapshot_dir", None) else default_recovery_snapshot_dir()
        snapshot_dir = Path(snapshot_dir).expanduser()
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_id = hashlib.sha256(f"{utc_now_iso()}:{reason}".encode("utf-8")).hexdigest()[:16]
        created_at = utc_now_iso()
        zip_path = snapshot_dir / f"snapshot_{created_at.replace(':', '').replace('-', '')}.zip"
        temp_dir = Path(tempfile.mkdtemp(prefix="recovery_snapshot_", dir=str(snapshot_dir)))
        try:
            sections: dict[str, Any] = {
                "metadata": {
                    "snapshot_id": snapshot_id,
                    "created_at": created_at,
                    "reason": reason,
                    "assessment_level": assessment.level if assessment else "",
                    "assessment_title": assessment.title if assessment else "",
                },
                "incident_awareness": assessment.to_dict() if assessment else {},
                "cleanup_preview": preview.to_dict() if preview else {},
                "database_export": self.db.export_snapshot(),
            }
            if current_scan_result is not None:
                sections["scan_result"] = json_safe(current_scan_result.to_dict())
                sections["findings"] = [json_safe(finding.to_dict()) for finding in current_scan_result.findings]
                sections["raw_logs"] = [json_safe(entry.to_dict()) for entry in current_scan_result.raw_logs]
                sections["timeline"] = current_scan_result.to_dict().get("collected_artifacts", {})
            if current_payload is not None:
                sections["current_payload"] = json_safe(current_payload)
            if current_payload is None and current_scan_result is not None:
                current_payload = current_scan_result.to_dict().get("collected_artifacts", {})
            sections["monitor_events"] = [event.to_dict() for event in self.db.recent_background_monitor_events(limit=500)]
            sections["notes"] = [note.to_dict() for note in self.db.list_investigation_notes(limit=500)]
            sections["forecast_state"] = self.db.latest_apple_security_forecast() or {}
            sections["persistence_inventory"] = {
                "launch_items": (current_payload or {}).get("launch_snapshots", []) if isinstance((current_payload or {}).get("launch_snapshots", []), list) else [],
            }
            sections["network_inventory"] = (current_payload or {}).get("network_discovery", {}) if isinstance((current_payload or {}).get("network_discovery", {}), dict) else {}
            sections["running_processes"] = (current_payload or {}).get("processes", {}) if isinstance((current_payload or {}).get("processes", {}), dict) else {}
            sections["hashes"] = (current_payload or {}).get("hashes", {}) if isinstance((current_payload or {}).get("hashes", {}), dict) else {}
            sections["browser_extension_inventory"] = (current_payload or {}).get("browser_extensions", []) if isinstance((current_payload or {}).get("browser_extensions", []), list) else []
            for name, payload in sections.items():
                (temp_dir / f"{name}.json").write_text(json.dumps(json_safe(payload), indent=2), encoding="utf-8")
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for child in sorted(temp_dir.glob("*.json")):
                    archive.write(child, arcname=child.name)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        snapshot_record = {
            "snapshot_id": snapshot_id,
            "created_at": created_at,
            "snapshot_path": str(zip_path),
            "assessment_level": assessment.level if assessment else "",
            "reason": reason,
            "payload_json": {
                "snapshot_id": snapshot_id,
                "created_at": created_at,
                "snapshot_path": str(zip_path),
                "assessment_level": assessment.level if assessment else "",
                "reason": reason,
            },
        }
        self.db.record_system_recovery_snapshot(snapshot_record)
        LOGGER.info("Snapshot created before cleanup snapshot_id=%s path=%s", snapshot_id, zip_path)
        return snapshot_record

    def _cleanup_selected_paths(self, selected_paths: list[str]) -> list[dict[str, Any]]:
        deleted: list[dict[str, Any]] = []
        for raw_path in selected_paths:
            path = self._normalize_path(raw_path)
            if self._is_protected(path) or not path.exists():
                continue
            entry = {
                "path": str(path),
                "size_bytes": self._dir_size(path),
                "kind": "directory" if path.is_dir() else "file",
                "last_modified": self._dir_mtime(path),
            }
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=False)
            else:
                path.unlink(missing_ok=True)
            deleted.append(entry)
        return deleted

    def run_cleanup(
        self,
        selected_paths: list[str],
        current_scan_result: ScanResult | None = None,
        current_payload: dict[str, Any] | None = None,
        *,
        create_snapshot_first: bool = False,
        preview: CleanupPreview | None = None,
        assessment: IncidentAwarenessAssessment | None = None,
    ) -> dict[str, Any]:
        assessment = assessment or self.incident_awareness_check(current_scan_result, current_payload)
        preview = preview or self.build_cleanup_preview(current_scan_result, current_payload)
        if create_snapshot_first:
            snapshot = self.create_evidence_snapshot(current_scan_result, current_payload, assessment, preview, reason="cleanup-snapshot-only")
            action = {
                "action_id": hashlib.sha256(f"{utc_now_iso()}:snapshot_only".encode("utf-8")).hexdigest()[:16],
                "created_at": utc_now_iso(),
                "action_type": "snapshot_only",
                "category": "system_recovery",
                "risk_level": assessment.level,
                "snapshot_id": snapshot["snapshot_id"],
                "preview_json": preview.to_dict(),
                "rollback_json": [],
                "deleted_json": [],
                "result_text": "Snapshot created. Cleanup was not performed.",
                "payload_json": {
                    "assessment": assessment.to_dict(),
                    "preview": preview.to_dict(),
                    "deleted": [],
                    "rollback_metadata": [],
                },
            }
            self.db.record_system_cleanup_action(action)
            LOGGER.info("Cleanup snapshot-only action recorded action_id=%s", action["action_id"])
            return {
                "action_type": "snapshot_only",
                "snapshot": snapshot,
                "deleted": [],
                "rollback_metadata": [],
                "result_text": "Snapshot created. Cleanup was not performed.",
                "assessment": assessment.to_dict(),
                "preview": preview.to_dict(),
            }
        selected_set = {str(path) for path in selected_paths}
        deletions = [candidate for candidate in preview.candidates if candidate.path in selected_set and not candidate.protected]
        snapshot = self.create_evidence_snapshot(current_scan_result, current_payload, assessment, preview, reason="cleanup")
        deleted = self._cleanup_selected_paths([item.path for item in deletions])
        rollback_metadata = [
            {
                "path": item["path"],
                "kind": item["kind"],
                "size_bytes": item["size_bytes"],
                "restore_hint": "Restore from snapshot or Time Machine if available.",
            }
            for item in deleted
        ]
        action = {
            "action_id": hashlib.sha256(f"{utc_now_iso()}:{len(deleted)}".encode("utf-8")).hexdigest()[:16],
            "created_at": utc_now_iso(),
            "action_type": "cleanup",
            "category": "system_recovery",
            "risk_level": assessment.level,
            "snapshot_id": snapshot["snapshot_id"],
            "preview_json": preview.to_dict(),
            "rollback_json": rollback_metadata,
            "deleted_json": deleted,
            "result_text": f"Deleted {len(deleted)} items after snapshot.",
            "payload_json": {
                "assessment": assessment.to_dict(),
                "preview": preview.to_dict(),
                "deleted": deleted,
                "rollback_metadata": rollback_metadata,
            },
        }
        self.db.record_system_cleanup_action(action)
        LOGGER.info("Cleanup action recorded action_id=%s deleted=%d", action["action_id"], len(deleted))
        return {
            "action_type": "cleanup",
            "snapshot": snapshot,
            "deleted": deleted,
            "rollback_metadata": rollback_metadata,
            "result_text": action["result_text"],
            "assessment": assessment.to_dict(),
            "preview": preview.to_dict(),
        }

    def build_context(self, current_scan_result: ScanResult | None = None, current_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        assessment = self.incident_awareness_check(current_scan_result, current_payload)
        preview = self.build_cleanup_preview(current_scan_result, current_payload)
        snapshot_history = self.db.list_system_recovery_snapshots(limit=20)
        cleanup_history = self.db.list_system_cleanup_actions(limit=20)
        return {
            "assessment": assessment.to_dict(),
            "preview": preview.to_dict(),
            "snapshot_history": snapshot_history,
            "cleanup_history": cleanup_history,
            "recovery_score": preview.recovery_score,
            "total_recoverable_bytes": preview.total_recoverable_bytes,
            "opportunities": preview.opportunities,
            "protected_paths": preview.protected_paths,
            "cache_age": "unknown",
            "generated_at": utc_now_iso(),
        }

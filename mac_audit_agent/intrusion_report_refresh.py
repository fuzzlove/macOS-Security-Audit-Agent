from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.intrusion_correlation import IntrusionCorrelationEngine, IntrusionCorrelationReport
from mac_audit_agent.runtime.app_paths import get_ai_summary_path
from mac_audit_agent.secure_io import MigrationResult, PersistenceResult

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IntrusionReportSnapshot:
    generation: str
    report: IntrusionCorrelationReport
    persistence: PersistenceResult
    migration: MigrationResult | None


class IntrusionReportRefreshCoordinator:
    """One immutable report and at most one persistence attempt per generation."""
    def __init__(self, engine: IntrusionCorrelationEngine) -> None:
        self.engine = engine; self._lock = threading.RLock(); self._cached: IntrusionReportSnapshot | None = None
        self._building = False; self._refresh_counter = 0; self._migration_checked = False; self.build_count = 0; self.persistence_attempt_count = 0

    def invalidate(self) -> None:
        with self._lock: self._cached = None

    def _generation(self, scan_result: Any) -> str:
        scan_id = str(getattr(scan_result, "scan_id", "no-scan")); timestamp = str(getattr(scan_result, "timestamp", ""))
        findings = len(getattr(scan_result, "findings", ()) or ())
        events = self.engine.db.recent_background_monitor_events(limit=1)
        event_key = ""
        if events:
            item = events[0]; event_key = f"{getattr(item, 'event_id', '')}:{getattr(item, 'timestamp', '')}"
        return f"{scan_id}:{timestamp}:{findings}:{event_key}:{self._refresh_counter}"

    def get(self, scan_result: Any = None, *, force: bool = False) -> IntrusionReportSnapshot:
        with self._lock:
            if force: self._refresh_counter += 1
            generation = self._generation(scan_result)
            if self._cached is not None and self._cached.generation == generation: return self._cached
            if self._building: raise RuntimeError("Reentrant intrusion report construction was blocked.")
            self._building = True
            try:
                report = self.engine.build_report(scan_result=scan_result); self.build_count += 1
                migration = None
                if not self._migration_checked:
                    self._migration_checked = True
                    try: migration = self.engine.migrate_legacy_ai_summary()
                    except (OSError, ValueError) as exc:
                        migration = MigrationResult(True, False, Path.home() / "reports" / "ai_summary.json", get_ai_summary_path(), "migration_failed", getattr(exc, "code", "REPORT_PATH_INVALID"))
                        LOGGER.warning("Legacy AI summary migration was skipped: code=%s", migration.error_code)
                self.persistence_attempt_count += 1
                try: persistence = self.engine.persist_ai_summary(report.ai_summary)
                except PermissionError:
                    LOGGER.exception("AI summary persistence permission failure for generation %s", generation)
                    persistence = PersistenceResult(True, False, get_ai_summary_path(), "REPORT_PERMISSION_DENIED", "Report could not be written with the current user permissions.")
                except OSError:
                    LOGGER.exception("AI summary persistence operating-system failure for generation %s", generation)
                    persistence = PersistenceResult(True, False, get_ai_summary_path(), "REPORT_ATOMIC_REPLACE_FAILED", "Atomic report replacement failed.")
                report.ai_summary_path = str(persistence.path) if persistence.succeeded and persistence.path else ""
                report.ai_summary_persistence = persistence.to_dict()
                if migration is not None:
                    report.ai_summary_persistence["legacy_migration"] = migration.to_dict()
                snapshot = IntrusionReportSnapshot(generation, report, persistence, migration)
                self._cached = snapshot
                return snapshot
            finally: self._building = False


def persistence_warning(result: PersistenceResult) -> str:
    if result.succeeded: return ""
    reason = {
        "REPORT_DIRECTORY_NOT_WRITABLE": "report directory is not writable by the current user",
        "REPORT_DIRECTORY_WRONG_OWNER": "report directory or target is owned by another user",
        "REPORT_DIRECTORY_IS_SYMLINK": "report directory is an unsafe symbolic link",
        "REPORT_TARGET_IS_SYMLINK": "report target is an unsafe symbolic link",
        "REPORT_PERMISSION_DENIED": "report directory is not writable by the current user",
        "REPORT_PATH_INVALID": "report path failed security validation",
        "REPORT_ATOMIC_REPLACE_FAILED": "atomic report replacement failed",
        "REPORT_SERIALIZATION_FAILED": "report JSON serialization failed",
    }.get(result.error_code or "", "report persistence failed")
    destination = str(result.path or get_ai_summary_path())
    return ("Intrusion analysis completed, but the AI summary could not be saved. "
            f"Destination: {destination}. Reason: {reason}. "
            "Run MSAA as the logged-in user and repair only this report directory's ownership or permissions.")


__all__ = ["IntrusionReportRefreshCoordinator", "IntrusionReportSnapshot", "persistence_warning"]

from __future__ import annotations

from pathlib import Path

from mac_audit_agent.quality.audit_models import AuditContext
from mac_audit_agent.quality.check_models import FunctionalCheck


DUPLICATE_HEADER_PATTERNS = {
    "settings_operational_health_primary": 'layout.addWidget(self._build_help_header("Operational Health", "operational_health"))',
    "settings_monitor_settings_primary": 'layout.addWidget(self._build_help_header("Monitor Settings", "settings"))',
    "apple_exposure_internal_title": 'header = QLabel("Apple Exposure Assessment")',
    "family_safety_internal_title": 'title = QLabel("Family & Safety Center")',
    "network_internal_title": 'title = QLabel("Network Intelligence")',
    "persistence_internal_title": 'title = QLabel("Persistence Intelligence")',
}


def run_ui_header_audit(context: AuditContext) -> list[FunctionalCheck]:
    check = FunctionalCheck(
        check_id="ui.headers.deduplicated",
        feature_area="UI",
        name="Duplicate page header audit",
        description="Major views should have one primary PageHeader and no repeated page title labels inside wrapped panels.",
        severity_if_failed="medium",
        test_type="static",
    )
    repo_root = Path(__file__).resolve().parents[2]
    files = {
        "mac_audit_agent/ui/main_window.py": repo_root / "mac_audit_agent/ui/main_window.py",
        "mac_audit_agent/ui/cve_radar_panel.py": repo_root / "mac_audit_agent/ui/cve_radar_panel.py",
        "mac_audit_agent/ui/family_safety_panel.py": repo_root / "mac_audit_agent/ui/family_safety_panel.py",
        "mac_audit_agent/ui/network_intelligence_panel.py": repo_root / "mac_audit_agent/ui/network_intelligence_panel.py",
        "mac_audit_agent/ui/persistence_intelligence_panel.py": repo_root / "mac_audit_agent/ui/persistence_intelligence_panel.py",
    }
    source = "\n".join(path.read_text() for path in files.values())
    matches = {
        name: pattern
        for name, pattern in DUPLICATE_HEADER_PATTERNS.items()
        if pattern in source
    }
    evidence = {
        "checked_files": sorted(files),
        "duplicate_patterns": sorted(matches),
    }
    if matches:
        return [
            check.failed(
                f"Duplicate page header patterns found: {', '.join(sorted(matches))}",
                "Keep one PageHeader per major view; rename repeated titles to specific section labels or remove them.",
                evidence,
            )
        ]
    return [check.passed("No duplicate primary page header patterns found.", evidence)]

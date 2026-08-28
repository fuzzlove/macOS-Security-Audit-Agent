from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.ui.severity_styles import display_severity_label
from mac_audit_agent.ui.severity_styles import normalize_severity as _normalize_ui_severity


SUPPORTED_SEVERITIES = {"informational", "info", "low", "medium", "high", "severe", "critical"}


@dataclass(frozen=True)
class FindingFilter:
    severity: str = ""
    scan_id: str | None = None
    source: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_severity(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if raw in {"informational", "information", "info"}:
        return "info"
    if raw == "severe":
        return "critical"
    return _normalize_ui_severity(value)


def display_filter_severity(value: Any) -> str:
    normalized = normalize_severity(value)
    if normalized == "info":
        return "Informational"
    return display_severity_label(normalized).title()


def apply_severity_filter(findings: list[dict[str, Any]], severity: Any) -> list[dict[str, Any]]:
    normalized = normalize_severity(severity)
    if normalized == "unknown":
        return list(findings)
    return [dict(finding) for finding in findings if normalize_severity(finding.get("severity", "info")) == normalized]


def clear_findings_filter() -> FindingFilter:
    return FindingFilter()


def get_active_filter_summary(finding_filter: FindingFilter | None, *, latest_scan: bool = True, match_count: int | None = None) -> str:
    if finding_filter is None or not finding_filter.severity:
        return "Showing all findings."
    label = display_filter_severity(finding_filter.severity)
    scan_text = "latest scan" if latest_scan else f"scan {finding_filter.scan_id}"
    if match_count == 0:
        return f"No {label} severity findings were found in the {scan_text}."
    return f"Showing {label} severity findings from {scan_text}."


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in ["info", "low", "medium", "high", "critical"]}
    for finding in findings:
        severity = normalize_severity(finding.get("severity", "info"))
        if severity in counts:
            counts[severity] += 1
    return counts


def validate_dashboard_severity_counts_match_findings(dashboard_counts: dict[str, int], findings: list[dict[str, Any]]) -> dict[str, Any]:
    filtered_counts = severity_counts(findings)
    mismatches = {
        severity: {"dashboard": int(dashboard_counts.get(severity, 0) or 0), "findings": count}
        for severity, count in filtered_counts.items()
        if int(dashboard_counts.get(severity, 0) or 0) != count
    }
    return {"status": "pass" if not mismatches else "warn", "dashboard_counts": dict(dashboard_counts), "filtered_counts": filtered_counts, "mismatches": mismatches}


__all__ = [
    "FindingFilter",
    "SUPPORTED_SEVERITIES",
    "normalize_severity",
    "display_filter_severity",
    "apply_severity_filter",
    "clear_findings_filter",
    "get_active_filter_summary",
    "severity_counts",
    "validate_dashboard_severity_counts_match_findings",
]

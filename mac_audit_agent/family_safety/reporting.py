from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from mac_audit_agent.reporting import get_reports_dir


REPORT_TITLE = "Family & Safety Configuration Report"


def _payload(recommendation: Any, apply_result: dict[str, Any] | None = None) -> dict[str, Any]:
    data = recommendation.to_dict() if hasattr(recommendation, "to_dict") else dict(recommendation)
    data["report_title"] = REPORT_TITLE
    data["apply_result"] = apply_result or {}
    data["timestamp_version"] = {
        "recommendation_id": data.get("recommendation_id", ""),
        "settings_version_after": (apply_result or {}).get("settings_version_after"),
    }
    return data


def default_family_safety_report_path(suffix: str = "json") -> Path:
    from datetime import datetime

    return get_reports_dir() / f"family_safety_configuration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{suffix}"


def export_family_safety_configuration_json(recommendation: Any, path: Path | None = None, apply_result: dict[str, Any] | None = None) -> Path:
    path = path or default_family_safety_report_path("json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_payload(recommendation, apply_result), indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def export_family_safety_configuration_markdown(recommendation: Any, path: Path | None = None, apply_result: dict[str, Any] | None = None) -> Path:
    path = path or default_family_safety_report_path("md")
    data = _payload(recommendation, apply_result)
    profile = data["selected_profile"]
    lines = [
        f"# {REPORT_TITLE}",
        "",
        f"Profile selected: {profile['display_name']}",
        "",
        "## User Answers",
        *[f"- {key}: {value}" for key, value in data.get("answers", {}).items()],
        "",
        "## Recommendation Reasoning",
        *[f"- {item}" for item in data.get("reasoning", [])],
        "",
        "## Proposed Changes",
    ]
    for change in data.get("proposed_changes", []):
        lines.append(f"- {change['setting_path']}: {change.get('current_value')} -> {change.get('proposed_value')} | {change.get('reason')} | {change.get('expected_effect')}")
    lines += ["", "## Applied Changes"]
    for change in (apply_result or {}).get("applied_changes", []):
        lines.append(f"- {change['setting_path']}: {change.get('current_value')} -> {change.get('proposed_value')}")
    lines += ["", "## Skipped Changes"]
    for change in (apply_result or {}).get("skipped_changes", []):
        lines.append(f"- {change['setting_path']}")
    lines += ["", "## Failed Changes"]
    for change in (apply_result or {}).get("failed_changes", []):
        lines.append(f"- {change['setting_path']}: {change.get('failure_reason', '')}")
    lines += ["", "## macOS and MDM Setup Actions"]
    for action in (apply_result or {}).get("system_setup_actions", []):
        lines.append(
            f"- {action.get('title', action.get('action_id', 'Action'))}: {action.get('status', 'not run')} | "
            f"changed={action.get('changed', False)} | verified={action.get('verified', False)} | {action.get('verification', '')}"
        )
    lines += [
        "",
        "## Expected Behavior",
        *[f"- {item}" for item in profile.get("expected_behavior", [])],
        "",
        "## Privacy Notes",
        *[f"- {item}" for item in data.get("privacy_notes", [])],
        "",
        "## Alert Expectations",
        *[f"- {change['setting_path']}: alert noise {change.get('alert_noise_impact')}" for change in data.get("proposed_changes", [])],
        "",
        "## Manual Review Checklist",
        *[f"- {item}" for item in data.get("manual_review_items", [])],
        "",
        "## Standards Alignment",
        *[f"- {item}" for item in data.get("standards_alignment", [])],
        "",
        "## Revert Plan",
        *[f"- {item}" for item in data.get("revert_plan", [])],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def export_family_safety_configuration_html(recommendation: Any, path: Path | None = None, apply_result: dict[str, Any] | None = None) -> Path:
    path = path or default_family_safety_report_path("html")
    md_path = export_family_safety_configuration_markdown(recommendation, path.with_suffix(".md"), apply_result)
    body = html.escape(md_path.read_text(encoding="utf-8"))
    path.write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>{REPORT_TITLE}</title></head><body><pre>{body}</pre></body></html>", encoding="utf-8")
    return path


def export_family_safety_configuration_word(recommendation: Any, path: Path | None = None, apply_result: dict[str, Any] | None = None) -> Path:
    from mac_audit_agent.professional_report import structured_payload_report

    path = path or default_family_safety_report_path("docx")
    return structured_payload_report(
        path,
        title=REPORT_TITLE,
        payload=_payload(recommendation, apply_result),
        qualification="Recommendations require authorized review; manual macOS controls are not changed by exporting this report.",
    )


def export_family_safety_configuration_excel(recommendation: Any, path: Path | None = None, apply_result: dict[str, Any] | None = None) -> Path:
    from mac_audit_agent.professional_report import structured_payload_report

    path = path or default_family_safety_report_path("xlsx")
    return structured_payload_report(
        path,
        title=REPORT_TITLE,
        payload=_payload(recommendation, apply_result),
        qualification="Static formula-free workbook; recommendations require authorized review.",
    )


__all__ = [
    "REPORT_TITLE",
    "default_family_safety_report_path",
    "export_family_safety_configuration_json",
    "export_family_safety_configuration_markdown",
    "export_family_safety_configuration_html",
    "export_family_safety_configuration_word",
    "export_family_safety_configuration_excel",
]

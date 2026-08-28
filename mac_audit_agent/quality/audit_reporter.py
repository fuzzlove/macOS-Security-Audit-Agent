from __future__ import annotations

import html
import json
from pathlib import Path

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.quality.audit_models import AuditReport, FunctionalCheck
from mac_audit_agent.quality.check_models import PreUATAuditResult


def default_output_dir() -> Path:
    from mac_audit_agent.reporting import get_reports_dir

    path = get_reports_dir() / "pre_uat"
    path.mkdir(parents=True, exist_ok=True)
    return path


def report_basename(hostname: str, timestamp: str | None = None) -> str:
    stamp = (timestamp or utc_now_iso()).replace(":", "").replace("-", "").replace("+", "Z")[:15]
    return f"Pre_UAT_Audit_redacted-host_{stamp}"


def write_reports(report: AuditReport, output_dir: Path | None = None) -> dict[str, str]:
    output_dir = output_dir or default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / report_basename(report.hostname, report.started_at)
    paths = {
        "json": str(base.with_suffix(".json")),
        "md": str(base.with_suffix(".md")),
        "html": str(base.with_suffix(".html")),
    }
    canonical = PreUATAuditResult.from_report(report).to_dict()
    Path(paths["json"]).write_text(json.dumps(canonical, indent=2, sort_keys=True), encoding="utf-8")
    Path(paths["md"]).write_text(markdown_report(report), encoding="utf-8")
    Path(paths["html"]).write_text(html_report(report), encoding="utf-8")
    report.output_paths.update(paths)
    Path(paths["json"]).write_text(json.dumps(canonical, indent=2, sort_keys=True), encoding="utf-8")
    return paths


def markdown_report(report: AuditReport) -> str:
    lines = [
        "# MSAA Pre-UAT Audit",
        "",
        f"Readiness Decision: **{report.readiness_decision}**",
        f"Started: {report.started_at}",
        f"Completed: {report.completed_at}",
        f"Mode: {report.mode}",
        "",
        "## Executive QA Summary",
        json.dumps(report.counts, indent=2, sort_keys=True),
    ]
    for title, statuses in [
        ("Blockers", {"BLOCKER"}),
        ("Critical Failures", {"FAIL"}),
        ("Warnings", {"WARN"}),
        ("Degraded", {"DEGRADED"}),
        ("Not Verified", {"NOT_VERIFIED"}),
        ("Harness Errors", {"HARNESS_ERROR"}),
        ("Passed Checks", {"PASS"}),
        ("Skipped Checks", {"SKIPPED"}),
    ]:
        lines.extend(["", f"## {title}"])
        selected = [check for check in report.checks if check.status in statuses]
        if not selected:
            lines.append("None.")
            continue
        for check in selected:
            lines.append(f"- [{check.status}] {check.check_id}: {check.name} - {check.actual_result or check.description}")
            if check.recommended_fix:
                lines.append(f"  Suggested fix: {check.recommended_fix}")
    lines.extend(["", "## User Testing Readiness Decision", report.readiness_decision])
    return "\n".join(lines) + "\n"


def html_report(report: AuditReport) -> str:
    rows = "\n".join(_check_row(check) for check in report.checks)
    counts = "".join(f"<li>{html.escape(key)}: {value}</li>" for key, value in report.counts.items())
    blocker_rows = "\n".join(_check_row(check) for check in report.checks if check.status == "BLOCKER") or "<tr><td colspan='6'>None</td></tr>"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MSAA Pre-UAT Audit</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 32px; color: #1f2933; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th, td {{ border: 1px solid #c9d2dc; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #263746; color: white; }}
.PASS {{ color: #1b7f3a; font-weight: 700; }}
.WARN {{ color: #9a6700; font-weight: 700; }}
.FAIL, .BLOCKER, .HARNESS_ERROR {{ color: #b42318; font-weight: 700; }}
.DEGRADED, .NOT_VERIFIED {{ color: #9a6700; font-weight: 700; }}
.SKIPPED {{ color: #667085; font-weight: 700; }}
</style></head><body>
<h1>MSAA Pre-UAT Audit</h1>
<h2>User Testing Readiness Decision: {html.escape(report.readiness_decision)}</h2>
<p>Started: {html.escape(report.started_at)}<br>Completed: {html.escape(report.completed_at)}<br>Mode: {html.escape(report.mode)}</p>
<h2>Executive QA Summary</h2><ul>{counts}</ul>
<h2>Blockers</h2><table><thead><tr><th>Status</th><th>ID</th><th>Area</th><th>Name</th><th>Actual</th><th>Suggested Fix</th></tr></thead><tbody>{blocker_rows}</tbody></table>
<h2>All Checks</h2><table><thead><tr><th>Status</th><th>ID</th><th>Area</th><th>Name</th><th>Actual</th><th>Suggested Fix</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""


def _check_row(check: FunctionalCheck) -> str:
    return (
        f"<tr><td class='{html.escape(check.status)}'>{html.escape(check.status)}</td>"
        f"<td>{html.escape(check.check_id)}</td><td>{html.escape(check.feature_area)}</td>"
        f"<td>{html.escape(check.name)}</td><td>{html.escape(check.actual_result)}</td>"
        f"<td>{html.escape(check.recommended_fix)}</td></tr>"
    )

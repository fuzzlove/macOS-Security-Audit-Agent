from __future__ import annotations

import html
import json
from pathlib import Path

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report
from mac_audit_agent.rootkit_detection.models import RootkitScanResult


def _safe_report_path(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if not path.exists():
            return path
        with path.open("a", encoding="utf-8"):
            return path
    except OSError:
        stamp = utc_now_iso().replace(":", "").replace("+", "Z")
        return path.with_name(f"{path.stem}_{stamp}{path.suffix}")


def export_rootkit_report_json(result: RootkitScanResult, path: Path) -> Path:
    path = _safe_report_path(path)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def export_rootkit_report_html(result: RootkitScanResult, path: Path) -> Path:
    path = _safe_report_path(path)
    findings = "\n".join(
        "<tr>"
        f"<td>{html.escape(item.severity.upper())}</td>"
        f"<td>{html.escape(item.confidence)}</td>"
        f"<td>{html.escape(item.title)}</td>"
        f"<td>{html.escape('; '.join(item.evidence[:4]))}</td>"
        f"<td>{html.escape(item.recommended_fix)}</td>"
        "</tr>"
        for item in result.findings
    ) or "<tr><td colspan='5'>No rootkit-like suspect findings were produced.</td></tr>"
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Rootkit & Advanced Persistence Suspect Review</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; color: #101828; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #D0D5DD; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #F2F4F7; }}
    .note {{ color: #475467; }}
  </style>
</head>
<body>
  <h1>Rootkit &amp; Advanced Persistence Suspect Review</h1>
  <p class="note">This defensive review identifies suspect indicators for analyst review. It does not claim a confirmed rootkit without sufficient evidence.</p>
  <h2>System Integrity Posture</h2>
  <ul>
    <li>SIP: {html.escape(result.posture.sip_status)}</li>
    <li>Authenticated Root: {html.escape(result.posture.authenticated_root_status)}</li>
    <li>SSV: {html.escape(result.posture.ssv_status)}</li>
    <li>Gatekeeper: {html.escape(result.posture.gatekeeper_status)}</li>
    <li>FileVault: {html.escape(result.posture.filevault_status)}</li>
  </ul>
  <h2>Rootkit Suspect Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Evidence</th><th>Recommended Fix</th></tr></thead>
    <tbody>{findings}</tbody>
  </table>
  <h2>Limitations</h2>
  <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in result.limitations) or '<li>None recorded.</li>'}</ul>
</body>
</html>"""
    path.write_text(body, encoding="utf-8")
    return path


def export_rootkit_report_professional(result: RootkitScanResult, path: Path) -> Path:
    path = _safe_report_path(path)
    posture = result.posture
    return write_professional_report(
        path,
        title="Rootkit & Advanced Persistence Suspect Review",
        sections=(ReportSection("System Integrity Posture", (
            f"SIP: {posture.sip_status}", f"Authenticated Root: {posture.authenticated_root_status}",
            f"SSV: {posture.ssv_status}", f"Gatekeeper: {posture.gatekeeper_status}", f"FileVault: {posture.filevault_status}",
        )),),
        tables=(ReportTable("Suspect Findings", ("Severity", "Confidence", "Title", "Evidence", "Suggested Fix"), tuple(
            (item.severity.upper(), item.confidence, item.title, "; ".join(item.evidence[:4]), item.recommended_fix)
            for item in result.findings
        )),),
        qualification="This defensive review identifies suspect indicators for analyst review. It does not claim a confirmed rootkit without sufficient evidence. " + "; ".join(result.limitations),
    )


__all__ = ["export_rootkit_report_html", "export_rootkit_report_json", "export_rootkit_report_professional"]

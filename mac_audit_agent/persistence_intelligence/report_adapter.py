from __future__ import annotations

import html
import json
from pathlib import Path

from mac_audit_agent.persistence_intelligence.models import PersistenceScanReport
from mac_audit_agent.ui.risk_colors import get_risk_colors, normalize_risk_label, risk_badge_html


def export_persistence_report_json(report: PersistenceScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict()
    for item in payload.get("items", []):
        label = normalize_risk_label(item.get("risk_level"), item.get("risk_score"))
        colors = get_risk_colors(label)
        item["risk_label"] = label
        item["risk_color"] = {"background": colors.background, "text": colors.text, "accent": colors.accent}
    for finding in payload.get("findings", []):
        label = normalize_risk_label(finding.get("severity"))
        colors = get_risk_colors(label)
        finding["risk_label"] = label
        finding["risk_color"] = {"background": colors.background, "text": colors.text, "accent": colors.accent}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def persistence_findings_as_msaa_findings(report: PersistenceScanReport) -> list[dict]:
    findings = []
    for finding in report.findings:
        item = next((candidate for candidate in report.items if candidate.item_id == finding.item_id), None)
        findings.append(
            {
                "id": finding.finding_id,
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity.lower(),
                "category": "Admin & Persistence",
                "description": finding.description,
                "evidence": "\n".join(finding.evidence),
                "evidence_summary": "; ".join(finding.evidence[:4]),
                "why_this_matters": finding.why_it_matters,
                "recommended_next_steps": finding.suggested_fix,
                "recommendation": finding.suggested_fix,
                "verification_steps": finding.validation_steps,
                "framework_mappings": finding.mitre_mapping,
                "source_detector": finding.source_scanner,
                "trigger_source": "persistence_intelligence",
                "file_path": item.path if item is not None else "",
                "related_path": item.executable_path if item is not None else "",
                "mitre_mapping": finding.mitre_mapping,
                "nist_mapping": finding.nist_mapping,
                "created_at": finding.created_at,
            }
        )
    return findings


def persistence_findings_as_sarif_inputs(report: PersistenceScanReport) -> list[dict]:
    return [
        {
            **finding,
            "rule_id": f"MSAA.Persistence.{finding.get('finding_id', 'finding')}",
            "command_used": "Persistence Intelligence read-only scanner",
        }
        for finding in persistence_findings_as_msaa_findings(report)
    ]


def export_persistence_report_markdown(report: PersistenceScanReport, path: Path) -> Path:
    lines = [
        "# Persistence Intelligence Report",
        "",
        f"Scan ID: `{report.scan_id}`",
        f"Posture score: **{report.posture_score}**",
        f"Items: **{len(report.items)}**",
        f"Findings: **{len(report.findings)}**",
        "",
        "## Top Findings",
    ]
    for finding in report.findings[:20]:
        lines.extend(["", f"### {finding.severity}: {finding.title}", finding.description, f"Suggested fix: {finding.suggested_fix}"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_persistence_report_html(report: PersistenceScanReport, path: Path) -> Path:
    item_by_id = {item.item_id: item for item in report.items}
    critical = sum(1 for finding in report.findings if finding.severity == "CRITICAL")
    high = sum(1 for finding in report.findings if finding.severity == "HIGH")
    top_findings = sorted(report.findings, key=lambda f: item_by_id.get(f.item_id).risk_score if item_by_id.get(f.item_id) else 0, reverse=True)[:10]
    top_rows = "\n".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td>{risk_badge_html(f.severity)}</td>"
        f"<td>{html.escape(item_by_id.get(f.item_id).label if item_by_id.get(f.item_id) else f.title)}</td>"
        f"<td>{html.escape(item_by_id.get(f.item_id).mechanism if item_by_id.get(f.item_id) else 'Unknown')}</td>"
        f"<td>{html.escape('; '.join(f.evidence[:2]) or f.description)}</td>"
        f"<td>{html.escape(f.suggested_fix)}</td>"
        "</tr>"
        for index, f in enumerate(top_findings, start=1)
    ) or '<tr><td colspan="6">No elevated persistence risks detected.</td></tr>'
    finding_rows = "\n".join(
        "<tr>"
        f"<td>{risk_badge_html(f.severity)}</td>"
        f"<td>{risk_badge_html(item_by_id.get(f.item_id).risk_level, item_by_id.get(f.item_id).risk_score) if item_by_id.get(f.item_id) else risk_badge_html(f.severity)}</td>"
        f"<td>{html.escape(f.confidence.upper())}</td>"
        f"<td>{html.escape(item_by_id.get(f.item_id).mechanism if item_by_id.get(f.item_id) else 'Unknown')}</td>"
        f"<td>{html.escape(item_by_id.get(f.item_id).label if item_by_id.get(f.item_id) else f.title)}</td>"
        f"<td>{html.escape((item_by_id.get(f.item_id).executable_path or item_by_id.get(f.item_id).program or item_by_id.get(f.item_id).path) if item_by_id.get(f.item_id) else '')}</td>"
        f"<td>{html.escape('; '.join(f.evidence[:3]) or f.description)}</td>"
        f"<td>{html.escape(f.suggested_fix)}</td>"
        f"<td>{html.escape(', '.join(f.mitre_mapping))}</td>"
        "</tr>"
        for f in report.findings
    ) or '<tr><td colspan="9">No persistence findings detected.</td></tr>'
    inventory_rows = "\n".join(
        "<tr>"
        f"<td>{risk_badge_html(item.risk_level, item.risk_score)}</td>"
        f"<td>{html.escape(str(item.risk_score))}</td>"
        f"<td>{risk_badge_html(item.trust_label, item.trust_score)}</td>"
        f"<td>{html.escape(str(item.trust_score))}</td>"
        f"<td>{risk_badge_html(item.baseline_status or 'unknown')}</td>"
        f"<td>{html.escape(item.mechanism)}</td>"
        f"<td>{html.escape(item.label or item.name or 'Unknown')}</td>"
        f"<td>{html.escape(item.path)}</td>"
        f"<td>{html.escape(item.executable_path or item.program or 'Unavailable')}</td>"
        f"<td>{html.escape('Yes' if item.loaded else 'No')}</td>"
        f"<td>{html.escape('Yes' if item.disabled else 'No')}</td>"
        f"<td>{html.escape(item.owner or 'Unknown')}:{html.escape(item.group or 'Unknown')}</td>"
        f"<td>{html.escape(item.permissions or 'Unknown')}</td>"
        f"<td>{html.escape(item.signed_status or 'Unknown')}</td>"
        "</tr>"
        for item in report.items
    ) or '<tr><td colspan="14">No persistence data available.</td></tr>'
    coverage_rows = "\n".join(
        f"<tr><td>{html.escape(str(c.get('scanner_id','')))}</td><td>{html.escape(str(c.get('coverage_status','')))}</td><td>{c.get('item_count',0)}</td><td>{c.get('finding_count',0)}</td></tr>"
        for c in report.coverage
    )
    body = f"""
    <html><head><style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #F8FAFC; color: #111827; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
    th, td {{ border: 1px solid #D0D5DD; padding: 6px 8px; text-align: left; vertical-align: top; }}
    th {{ background: #1F2937; color: #FFFFFF; }}
    .risk-badge {{ white-space: nowrap; }}
    </style></head><body>
    <h1>Persistence Intelligence Report</h1>
    <h2>Summary</h2>
    <table><tr><th>Total Persistence Items</th><th>Critical Findings</th><th>High Findings</th><th>Scanner Coverage Rows</th><th>Last Scan</th></tr>
    <tr><td>{len(report.items)}</td><td>{critical}</td><td>{high}</td><td>{len(report.coverage)}</td><td>{html.escape(report.completed_at)}</td></tr></table>
    <p>Posture score: <strong>{report.posture_score}</strong></p>
    <h2>Top Persistence Risks</h2>
    <table><tr><th>Rank</th><th>Severity</th><th>Item</th><th>Mechanism</th><th>Risk Reason</th><th>Action</th></tr>{top_rows}</table>
    <h2>Persistence Inventory</h2>
    <table><tr><th>Risk</th><th>Risk Score</th><th>Trust</th><th>Trust Score</th><th>Baseline</th><th>Mechanism</th><th>Label</th><th>Path</th><th>Target</th><th>Loaded</th><th>Disabled</th><th>Owner</th><th>Permissions</th><th>Signature</th></tr>{inventory_rows}</table>
    <h2>Persistence Findings</h2>
    <table><tr><th>Severity</th><th>Risk</th><th>Confidence</th><th>Mechanism</th><th>Name / Label</th><th>Target Path</th><th>Why Flagged</th><th>Recommended Action</th><th>MITRE</th></tr>{finding_rows}</table>
    <h2>Coverage</h2>
    <table><tr><th>Scanner</th><th>Status</th><th>Items</th><th>Findings</th></tr>{coverage_rows}</table>
    <h2>Limitations</h2>
    <p>Read-only scan. Permission-limited locations are reported as partial coverage.</p>
    </body></html>
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path

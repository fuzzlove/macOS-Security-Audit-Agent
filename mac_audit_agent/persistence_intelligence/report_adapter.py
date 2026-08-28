from __future__ import annotations

import html
import hashlib
import json
import zipfile
import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report
from mac_audit_agent.persistence_intelligence.models import PersistenceScanReport
from mac_audit_agent.telemetry.privacy import redact_command_line
from mac_audit_agent.ui.risk_colors import get_risk_colors, normalize_risk_label, risk_badge_html


REPORT_BRAND = "Liquidsky Network Security"
REPORT_TITLE = "Persistence Intelligence Report"
REPORT_MARK = "⛨"
REPORT_CLASSIFICATION = "Security Assessment — Consultant Work Product"


def _safe_report_payload(report: PersistenceScanReport) -> dict:
    payload = report.to_dict()
    payload["report_metadata"] = {
        "organization": REPORT_BRAND,
        "title": REPORT_TITLE,
        "classification": REPORT_CLASSIFICATION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "content_safety": "Static report; no macros, scripts, formulas, external relationships, or embedded executables.",
    }
    item_records = list(payload.get("items", []))
    for scanner_result in payload.get("scanner_results", []):
        if isinstance(scanner_result, dict):
            item_records.extend(scanner_result.get("items", []))
    for item in item_records:
        arguments = item.get("program_arguments", [])[:64]
        item["program_arguments"] = [redact_command_line(" ".join(str(argument) for argument in arguments))] if arguments else []
    return payload


def _mechanism_rows(report: PersistenceScanReport) -> tuple[tuple[object, ...], ...]:
    item_counts = Counter(item.mechanism or "Unknown" for item in report.items)
    finding_counts = Counter()
    highest_risk: dict[str, int] = {}
    items_by_id = {item.item_id: item for item in report.items}
    for item in report.items:
        mechanism = item.mechanism or "Unknown"
        highest_risk[mechanism] = max(highest_risk.get(mechanism, 0), item.risk_score)
    for finding in report.findings:
        item = items_by_id.get(finding.item_id)
        finding_counts[item.mechanism if item else "Unknown"] += 1
    return tuple(
        (mechanism, count, finding_counts.get(mechanism, 0), highest_risk.get(mechanism, 0))
        for mechanism, count in sorted(item_counts.items(), key=lambda value: (-value[1], value[0].lower()))
    )


def _coverage_status(report: PersistenceScanReport) -> str:
    states = {str(row.get("coverage_status", "unknown")).lower() for row in report.coverage}
    if report.errors or states & {"failed", "error", "unavailable"}:
        return "DEGRADED"
    if report.warnings or states & {"partial", "degraded", "unknown"}:
        return "PARTIAL"
    return "COMPLETE"


def export_persistence_report_json(report: PersistenceScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _safe_report_payload(report)
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


def export_persistence_incident_bundle(report: PersistenceScanReport, path: Path) -> Path:
    """Create a bounded forensic bundle without copying credentials or binaries."""
    path.parent.mkdir(parents=True, exist_ok=True)
    report_payload = _safe_report_payload(report)
    evidence_manifest: list[dict[str, object]] = []
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        report_bytes = json.dumps(report_payload, indent=2, sort_keys=True).encode("utf-8")
        archive.writestr("report/persistence_report.json", report_bytes)
        archive.writestr("report/persistence_report.txt", persistence_report_text(report).encode("utf-8"))
        for item in report.items:
            source = Path(item.plist_path or item.path).expanduser()
            record: dict[str, object] = {
                "item_id": item.item_id,
                "path": str(source),
                "mechanism": item.mechanism,
                "sha256": item.target_hash_sha256,
                "copied": False,
                "reason": "metadata_only",
            }
            # Plists are necessary configuration evidence. SSH keys, shell
            # profiles, scripts, application data and binaries remain metadata-
            # only because they may contain credentials or sensitive content.
            if item.plist_path and source.suffix == ".plist" and source.is_file() and not source.is_symlink():
                try:
                    data = source.read_bytes()
                    if len(data) <= 2_000_000:
                        digest = hashlib.sha256(data).hexdigest()
                        archive.writestr(f"evidence/plists/{item.item_id}.plist", data)
                        record.update({"copied": True, "reason": "bounded_plist_evidence", "configuration_sha256": digest})
                    else:
                        record["reason"] = "configuration_exceeds_2mb_limit"
                except OSError as exc:
                    record["reason"] = f"read_failed:{type(exc).__name__}"
            evidence_manifest.append(record)
        manifest = {
            "schema_version": 1,
            "scan_id": report.scan_id,
            "created_at": report.completed_at,
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "evidence": evidence_manifest,
            "collection_method": "MSAA local read-only Persistence Intelligence scan",
            "chain_of_custody": {
                "collected_at_utc": datetime.now(timezone.utc).isoformat(),
                "handling": "Preserve the original archive read-only; work from a verified copy; record every transfer and SHA-256 hash.",
            },
            "limitations": ["Credentials, SSH key material, shell profiles, scripts, application data, and executable binaries are metadata-only by default."],
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
        archive.writestr(
            "RESPONDER_README.txt",
            (
                "PERSISTENCE INCIDENT RESPONSE EVIDENCE\n\n"
                "1. If active compromise is suspected, follow organizational authority and isolation procedures; do not delete artifacts.\n"
                "2. Record reporter, affected device, time observed, business impact, and incident/ticket number.\n"
                "3. Preserve this original archive read-only and calculate SHA-256 before transfer. Analyze only a verified copy.\n"
                "4. Provide the manifest, scan ID, timestamps, findings, coverage gaps, and limitations to the incident responder.\n"
                "5. Record each custodian, transfer time, purpose, and hash. Escalate critical findings through the approved incident channel.\n"
                "6. This bundle intentionally excludes credentials, private keys, scripts, binaries, and application data by default.\n"
            ).encode("utf-8"),
        )
    return path


def _coverage_explanation(report: PersistenceScanReport, row: dict) -> tuple[str, str]:
    scanner_id = str(row.get("scanner_id", "Unknown"))
    result = next((candidate for candidate in report.scanner_results if candidate.scanner_id == scanner_id), None)
    warnings = list(getattr(result, "warnings", []) or [])
    errors = list(getattr(result, "errors", []) or [])
    status = str(row.get("coverage_status", "unknown")).lower()
    if errors:
        cause = "Failed because: " + "; ".join(errors)
        action = "Resolve the reported collector errors, confirm permissions and paths, then rerun the scan. Do not treat this surface as passing until it completes."
    elif warnings:
        cause = "Partial/degraded because: " + "; ".join(warnings)
        action = "Review each limitation, grant only approved read access if required, validate the uncovered locations manually, and rerun the scan."
    elif status in {"healthy", "clean", "pass", "passed", "complete"}:
        cause = f"Passed: scanner completed without reported warnings or errors; {row.get('item_count', 0)} item(s) and {row.get('finding_count', 0)} finding(s) were recorded."
        action = "No scanner fault was reported. Investigate any findings separately and keep the scan current; a pass means collection completed, not that compromise is impossible."
    else:
        cause = f"Status is {status or 'unknown'} and the scanner supplied no detailed warning or error."
        action = "Review Diagnostics and validate this persistence surface manually before assigning a passing rating."
    return cause, action


def persistence_report_text(report: PersistenceScanReport) -> str:
    item_by_id = {item.item_id: item for item in report.items}
    lines = [
        f"{REPORT_MARK} {REPORT_BRAND.upper()}",
        "PERSISTENCE INTELLIGENCE REPORT",
        REPORT_CLASSIFICATION,
        "Prepared by MSAA Persistence Intelligence",
        "",
        f"Scan ID: {report.scan_id}",
        f"Started: {report.started_at}",
        f"Completed: {report.completed_at}",
        f"Posture score: {report.posture_score}/100",
        f"Items: {len(report.items)} | Findings: {len(report.findings)}",
        f"Collection coverage: {_coverage_status(report)}",
        "",
        "EXECUTIVE SUMMARY",
        "This report inventories persistence mechanisms observed by the local, read-only MSAA assessment. Findings identify conditions requiring validation; they do not by themselves prove malicious activity.",
        "",
        "MECHANISM SUMMARY",
    ]
    lines.extend(
        f"{mechanism}: {items} item(s), {findings} finding(s), highest risk {risk}/100"
        for mechanism, items, findings, risk in _mechanism_rows(report)
    )
    if not report.items:
        lines.append("No persistence mechanisms were collected; review scanner coverage before interpreting this result.")
    lines.extend(["", "PERSISTENCE INVENTORY"])
    for item in sorted(report.items, key=lambda candidate: (-candidate.risk_score, candidate.mechanism.lower(), candidate.path.lower())):
        lines.extend([
            f"[{item.risk_level} {item.risk_score}/100] {item.mechanism} — {item.label or item.name or 'Unnamed item'}",
            f"Configuration: {item.path or 'Unavailable'}",
            f"Executable/target: {item.executable_path or item.program or 'Unavailable'}",
            f"Owner: {item.owner or 'Unknown'}:{item.group or 'Unknown'} | Permissions: {item.permissions or 'Unknown'}",
            f"Signature: {item.signed_status or 'Unknown'} | Team ID: {item.team_id or 'Unavailable'} | Baseline: {item.baseline_status or 'Unknown'}",
            f"Loaded: {'Yes' if item.loaded else 'No'} | Disabled: {'Yes' if item.disabled else 'No'} | First seen: {item.first_seen or 'Unknown'} | Last seen: {item.last_seen or 'Unknown'}",
            "",
        ])
    if not report.items:
        lines.extend(["No persistence items were collected. This is not evidence of absence when coverage is partial.", ""])
    lines.extend([
        "FINDINGS",
    ])
    for finding in report.findings:
        item = item_by_id.get(finding.item_id)
        lines.extend([
            f"[{finding.severity}] {finding.title}",
            f"Artifact: {(item.path if item else 'Unknown')}",
            f"Why flagged: {'; '.join(finding.evidence) or finding.description}",
            f"Why it matters: {finding.why_it_matters}",
            f"Recommended action: {finding.suggested_fix}",
            "",
        ])
    if not report.findings:
        lines.extend(["No findings were reported. This does not eliminate coverage limitations.", ""])
    lines.append("SCANNER COVERAGE")
    for row in report.coverage:
        cause, action = _coverage_explanation(report, row)
        lines.extend([f"{row.get('scanner_id', 'Unknown')}: {row.get('coverage_status', 'Unknown')}", cause, f"How to reach/retain pass: {action}", ""])
    lines.extend([
        "INCIDENT REPORTING / EVIDENCE HANDLING",
        "Preserve original evidence; do not delete suspicious persistence during triage. Record device, reporter, UTC time, business impact, and incident number.",
        "Hash exported evidence with SHA-256, analyze a verified copy, document every transfer, and report critical findings through the approved incident-response channel.",
        "Limitations: permission-limited or failed scanners are not passing evidence. Static reports intentionally do not embed executable content.",
        "",
        f"Prepared by {REPORT_BRAND}. {REPORT_CLASSIFICATION}.",
    ])
    return "\n".join(lines)


def export_persistence_report_text(report: PersistenceScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(persistence_report_text(report), encoding="utf-8")
    return path


def export_persistence_report_csv(report: PersistenceScanReport, path: Path) -> Path:
    """Export a static, formula-safe flat inventory suitable for spreadsheet import."""
    path.parent.mkdir(parents=True, exist_ok=True)
    item_by_id = {item.item_id: item for item in report.items}
    fields = (
        "organization", "report", "scan_id", "record_type", "severity", "risk_score", "confidence",
        "mechanism", "label", "configuration_path", "executable_or_target", "owner", "group", "permissions",
        "signature", "team_id", "baseline", "loaded", "disabled", "first_seen", "last_seen", "evidence",
        "recommended_action", "source",
    )

    def safe(value: object) -> str:
        text = str(value if value is not None else "")
        return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text

    records: list[dict[str, object]] = []
    for item in report.items:
        records.append({
            "organization": REPORT_BRAND, "report": REPORT_TITLE, "scan_id": report.scan_id, "record_type": "inventory",
            "severity": item.risk_level, "risk_score": item.risk_score, "confidence": item.confidence,
            "mechanism": item.mechanism, "label": item.label or item.name, "configuration_path": item.path,
            "executable_or_target": item.executable_path or item.program, "owner": item.owner, "group": item.group,
            "permissions": item.permissions, "signature": item.signed_status, "team_id": item.team_id,
            "baseline": item.baseline_status, "loaded": item.loaded, "disabled": item.disabled,
            "first_seen": item.first_seen, "last_seen": item.last_seen, "evidence": "; ".join(item.evidence),
            "recommended_action": item.recommended_verification, "source": item.source_scanner,
        })
    for finding in report.findings:
        item = item_by_id.get(finding.item_id)
        records.append({
            "organization": REPORT_BRAND, "report": REPORT_TITLE, "scan_id": report.scan_id, "record_type": "finding",
            "severity": finding.severity, "risk_score": item.risk_score if item else "", "confidence": finding.confidence,
            "mechanism": item.mechanism if item else "Unknown", "label": finding.title,
            "configuration_path": item.path if item else "", "executable_or_target": (item.executable_path or item.program) if item else "",
            "owner": item.owner if item else "", "group": item.group if item else "", "permissions": item.permissions if item else "",
            "signature": item.signed_status if item else "", "team_id": item.team_id if item else "",
            "baseline": item.baseline_status if item else "", "loaded": item.loaded if item else "",
            "disabled": item.disabled if item else "", "first_seen": item.first_seen if item else finding.created_at,
            "last_seen": item.last_seen if item else finding.created_at, "evidence": "; ".join(finding.evidence),
            "recommended_action": finding.suggested_fix, "source": finding.source_scanner,
        })
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(fields)
        for record in records:
            writer.writerow([safe(record.get(field, "")) for field in fields])
    return path


def export_persistence_report_docx(report: PersistenceScanReport, path: Path) -> Path:
    return _export_persistence_professional(report, path)


def export_persistence_report_excel(report: PersistenceScanReport, path: Path) -> Path:
    return _export_persistence_professional(report, path)


def _export_persistence_professional(report: PersistenceScanReport, path: Path) -> Path:
    item_by_id = {item.item_id: item for item in report.items}
    finding_rows = tuple(
        (
            finding.severity, finding.confidence, finding.title,
            item_by_id.get(finding.item_id).path if item_by_id.get(finding.item_id) else "",
            "; ".join(finding.evidence), finding.why_it_matters, finding.suggested_fix,
            ", ".join(finding.mitre_mapping),
        )
        for finding in report.findings
    )
    inventory_rows = tuple(
        (
            item.risk_level, item.risk_score, item.mechanism, item.label or item.name,
            item.path, item.executable_path or item.program, item.owner, item.permissions,
            item.signed_status, item.team_id, item.baseline_status, "Yes" if item.loaded else "No",
            "Yes" if item.disabled else "No", item.first_seen, item.last_seen,
        )
        for item in sorted(report.items, key=lambda candidate: (-candidate.risk_score, candidate.mechanism.lower(), candidate.path.lower()))
    )
    coverage_rows = tuple(
        (
            row.get("scanner_id", "Unknown"), row.get("coverage_status", "Unknown"),
            row.get("item_count", 0), row.get("finding_count", 0),
            _coverage_explanation(report, row)[0], _coverage_explanation(report, row)[1],
        )
        for row in report.coverage
    )
    return write_professional_report(
        path,
        title=f"{REPORT_MARK} {REPORT_BRAND} — {REPORT_TITLE}",
        sections=(
            ReportSection("Executive Summary", (
                REPORT_CLASSIFICATION,
                f"Scan ID: {report.scan_id}",
                f"Assessment window: {report.started_at} to {report.completed_at}",
                f"Posture score: {report.posture_score}/100",
                f"Inventory: {len(report.items)} persistence item(s); {len(report.findings)} finding(s)",
                f"Collection coverage: {_coverage_status(report)}",
                "Findings identify conditions requiring analyst validation and do not, by themselves, establish malicious activity.",
            )),
            ReportSection("Method and Evidence Handling", (
                "MSAA performed a local, read-only inventory of supported persistence surfaces and correlated ownership, permissions, signature, baseline, and target metadata.",
                "Preserve suspicious artifacts during triage. Hash evidence with SHA-256, analyze a verified copy, and record transfers under the applicable incident process.",
            )),
        ),
        tables=(
            ReportTable("Mechanism Breakdown", ("Mechanism", "Items", "Findings", "Highest Risk Score"), _mechanism_rows(report)),
            ReportTable("Persistence Findings", ("Severity", "Confidence", "Title", "Artifact", "Evidence", "Why It Matters", "Recommended Action", "MITRE ATT&CK"), finding_rows),
            ReportTable("Complete Persistence Inventory", ("Risk", "Score", "Mechanism", "Label", "Configuration Path", "Executable / Target", "Owner", "Permissions", "Signature", "Team ID", "Baseline", "Loaded", "Disabled", "First Seen", "Last Seen"), inventory_rows),
            ReportTable("Scanner Coverage", ("Scanner", "Status", "Items", "Findings", "Coverage Explanation", "Required Follow-up"), coverage_rows),
        ),
        qualification=(
            "Static consultant report: no macros, formulas, scripts, external relationships, or embedded executables. "
            "Permission-limited or failed scanners are not passing evidence. This report supports investigation and does not certify the endpoint or prove compromise."
        ),
    )


def export_persistence_report_pdf(report: PersistenceScanReport, path: Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        # Headless fallback: emit a minimal static PDF using a built-in PDF
        # font. Do not initialize Qt here; CLI/report workers may not own a
        # QGuiApplication and Qt aborts during font database access.
        path.parent.mkdir(parents=True, exist_ok=True)
        source_lines = persistence_report_text(report).splitlines()
        lines = [chunk for raw in source_lines for chunk in ([raw[index:index + 92] for index in range(0, len(raw), 92)] or [""])]
        pages = [lines[index:index + 52] for index in range(0, len(lines), 52)] or [[""]]
        objects: list[bytes] = []
        # Object numbers: catalog=1, pages=2, font=3, then page/content pairs.
        kids = " ".join(f"{4 + index * 2} 0 R" for index in range(len(pages)))
        objects.extend([
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ])
        for index, page_lines in enumerate(pages):
            page_number = 4 + index * 2
            content_number = page_number + 1
            commands = ["BT", "/F1 9 Tf", "44 748 Td", "12 TL"]
            for line in page_lines:
                safe = line.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                commands.extend([f"({safe}) Tj", "T*"])
            commands.append("ET")
            stream = "\n".join(commands).encode("latin-1")
            objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_number} 0 R >>".encode("ascii"))
            objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
        payload = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, obj in enumerate(objects, start=1):
            offsets.append(len(payload))
            payload.extend(f"{number} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
        xref = len(payload)
        payload.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
        payload.extend(b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:]))
        payload.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
        path.write_bytes(payload)
        return path
    class ShieldMark(Flowable):
        def __init__(self) -> None:
            super().__init__()
            self.width = 34
            self.height = 42

        def draw(self) -> None:
            self.canv.setFillColor(colors.HexColor("#123A63"))
            outline = self.canv.beginPath()
            outline.moveTo(17, 42)
            outline.lineTo(32, 35)
            outline.lineTo(29, 14)
            outline.curveTo(27, 7, 22, 3, 17, 0)
            outline.curveTo(12, 3, 7, 7, 5, 14)
            outline.lineTo(2, 35)
            outline.close()
            self.canv.drawPath(outline, fill=1, stroke=0)
            self.canv.setStrokeColor(colors.HexColor("#4CA6D8"))
            self.canv.setLineWidth(2)
            self.canv.line(17, 34, 17, 9)
            self.canv.line(9, 27, 25, 27)

    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("LiquidSkyTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=18, leading=21, textColor=colors.HexColor("#123A63"), alignment=TA_LEFT, spaceAfter=2)
    subtitle_style = ParagraphStyle("LiquidSkySubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=colors.HexColor("#52677C"))
    heading_style = ParagraphStyle("LiquidSkyHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.HexColor("#123A63"), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle("LiquidSkyBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=colors.HexColor("#25364A"))
    cell_style = ParagraphStyle("LiquidSkyCell", parent=body_style, fontSize=6.4, leading=8)
    header_style = ParagraphStyle("LiquidSkyTableHeader", parent=cell_style, fontName="Helvetica-Bold", textColor=colors.white)

    def paragraph(value: object, style=cell_style) -> Paragraph:
        return Paragraph(html.escape(str(value or "Unavailable")).replace("\n", "<br/>"), style)

    def report_table(headers: tuple[str, ...], rows: list[tuple[object, ...]], widths: list[float] | None = None) -> Table:
        data = [[paragraph(value, header_style) for value in headers]]
        data.extend([paragraph(value) for value in row] for row in rows)
        if not rows:
            data.append([paragraph("No records.")] + [paragraph("") for _ in headers[1:]])
        table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123A63")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B9C6D3")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    page_width, _page_height = landscape(letter)
    document = SimpleDocTemplate(
        str(path), pagesize=landscape(letter), rightMargin=0.45 * inch, leftMargin=0.45 * inch,
        topMargin=0.45 * inch, bottomMargin=0.45 * inch,
        title=f"{REPORT_BRAND} — {REPORT_TITLE}", author=REPORT_BRAND, subject=REPORT_CLASSIFICATION,
    )
    brand = Table(
        [[ShieldMark(), Paragraph(f"{REPORT_BRAND}<br/><font size='10'>{REPORT_TITLE}</font>", title_style)]],
        colWidths=[0.55 * inch, page_width - 1.5 * inch], hAlign="LEFT",
    )
    brand.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story = [
        brand,
        Paragraph(REPORT_CLASSIFICATION, subtitle_style),
        Spacer(1, 8),
        Paragraph("Executive Summary", heading_style),
        report_table(
            ("Scan ID", "Assessment Window", "Posture", "Inventory", "Findings", "Coverage"),
            [(report.scan_id, f"{report.started_at} — {report.completed_at}", f"{report.posture_score}/100", len(report.items), len(report.findings), _coverage_status(report))],
            [1.25 * inch, 2.35 * inch, 0.75 * inch, 0.65 * inch, 0.65 * inch, 0.8 * inch],
        ),
        Paragraph("Findings identify conditions requiring analyst validation and do not, by themselves, establish malicious activity.", body_style),
        Paragraph("Persistence Mechanism Breakdown", heading_style),
        report_table(("Mechanism", "Items", "Findings", "Highest Risk Score"), list(_mechanism_rows(report)), [2.5 * inch, 0.75 * inch, 0.75 * inch, 1.1 * inch]),
        Paragraph("Persistence Findings", heading_style),
    ]
    item_by_id = {item.item_id: item for item in report.items}
    finding_rows = [
        (
            finding.severity, finding.confidence, finding.title,
            item_by_id.get(finding.item_id).path if item_by_id.get(finding.item_id) else "Unknown",
            "; ".join(finding.evidence) or finding.description, finding.suggested_fix,
        )
        for finding in report.findings
    ]
    story.extend([
        report_table(("Severity", "Confidence", "Finding", "Artifact", "Evidence", "Recommended Action"), finding_rows, [0.65 * inch, 0.75 * inch, 1.25 * inch, 1.8 * inch, 2.15 * inch, 2.1 * inch]),
        PageBreak(),
        Paragraph("Complete Persistence Inventory", heading_style),
    ])
    inventory_rows = [
        (
            f"{item.risk_level} {item.risk_score}/100", item.mechanism, item.label or item.name,
            item.path, item.executable_path or item.program, f"{item.owner or 'Unknown'} / {item.permissions or 'Unknown'}",
            f"{item.signed_status or 'Unknown'} / {item.team_id or 'No Team ID'}", item.baseline_status,
        )
        for item in sorted(report.items, key=lambda candidate: (-candidate.risk_score, candidate.mechanism.lower(), candidate.path.lower()))
    ]
    story.extend([
        report_table(("Risk", "Mechanism", "Label", "Configuration Path", "Executable / Target", "Owner / Permissions", "Signature / Team", "Baseline"), inventory_rows, [0.75 * inch, 0.9 * inch, 1.0 * inch, 1.65 * inch, 1.65 * inch, 1.15 * inch, 1.1 * inch, 0.75 * inch]),
        Paragraph("Scanner Coverage and Limitations", heading_style),
    ])
    coverage_rows = [
        (row.get("scanner_id", "Unknown"), row.get("coverage_status", "Unknown"), row.get("item_count", 0), row.get("finding_count", 0), *_coverage_explanation(report, row))
        for row in report.coverage
    ]
    story.extend([
        report_table(("Scanner", "Status", "Items", "Findings", "Coverage Explanation", "Required Follow-up"), coverage_rows, [1.15 * inch, 0.7 * inch, 0.5 * inch, 0.55 * inch, 3.1 * inch, 3.25 * inch]),
        Paragraph("Method and Evidence Handling", heading_style),
        Paragraph("MSAA performed a local, read-only inventory of supported persistence surfaces. Preserve suspicious artifacts during triage; hash evidence with SHA-256, analyze a verified copy, and record every transfer.", body_style),
        Spacer(1, 6),
        Paragraph("Static consultant report: no macros, formulas, scripts, external relationships, or embedded executables. Permission-limited or failed scanners are not passing evidence. This report does not certify the endpoint or prove compromise.", subtitle_style),
    ])

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#B9C6D3"))
        canvas.line(doc.leftMargin, 22, page_width - doc.rightMargin, 22)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#52677C"))
        canvas.drawString(doc.leftMargin, 11, f"{REPORT_BRAND} | Scan {report.scan_id}")
        canvas.drawRightString(page_width - doc.rightMargin, 11, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
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
                "cis_mapping": finding.cis_mapping,
                "cvss_score": finding.cvss_score,
                "analyst_status": item.analyst_status if item is not None else "open",
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
    lines = ["# " + line if index == 0 else line for index, line in enumerate(persistence_report_text(report).splitlines())]
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
        "<tr>"
        f"<td>{html.escape(str(c.get('scanner_id','')))}</td>"
        f"<td>{html.escape(str(c.get('coverage_status','')))}</td>"
        f"<td>{c.get('item_count',0)}</td><td>{c.get('finding_count',0)}</td>"
        f"<td>{html.escape(_coverage_explanation(report, c)[0])}</td>"
        f"<td>{html.escape(_coverage_explanation(report, c)[1])}</td>"
        "</tr>"
        for c in report.coverage
    )
    mechanism_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(mechanism))}</td><td>{items}</td><td>{findings}</td><td>{risk}/100</td>"
        "</tr>"
        for mechanism, items, findings, risk in _mechanism_rows(report)
    ) or '<tr><td colspan="4">No persistence mechanisms were collected. Review coverage before interpreting this result.</td></tr>'
    body = f"""
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(REPORT_BRAND)} — {html.escape(REPORT_TITLE)}</title><style>
    :root {{ color-scheme: light; --navy:#123A63; --blue:#23658F; --ink:#172033; --muted:#52677C; --line:#C8D3DE; --paper:#FFFFFF; --wash:#F3F6F9; }}
    * {{ box-sizing: border-box; }} body {{ margin:0; font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#E9EEF3; color:var(--ink); }}
    main {{ max-width:1320px; margin:24px auto; padding:36px 42px; background:var(--paper); box-shadow:0 10px 32px rgba(18,58,99,.10); }}
    .brand {{ display:flex; align-items:center; gap:16px; padding-bottom:18px; border-bottom:3px solid var(--navy); }}
    .brand svg {{ width:48px; height:56px; flex:none; }} .brand-name {{ color:var(--navy); font-size:20px; font-weight:750; letter-spacing:.025em; }}
    .report-name {{ margin-top:2px; color:var(--muted); font-size:15px; }} .classification {{ margin:12px 0 24px; color:var(--muted); font-size:11px; letter-spacing:.04em; text-transform:uppercase; }}
    h1 {{ position:absolute; left:-10000px; }} h2 {{ margin:28px 0 10px; padding-bottom:6px; color:var(--navy); font-size:17px; border-bottom:1px solid var(--line); }}
    table {{ border-collapse:collapse; width:100%; margin:12px 0; font-size:11px; }}
    th, td {{ border:1px solid var(--line); padding:7px 8px; text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
    th {{ background:var(--navy); color:#FFFFFF; font-weight:650; }} tbody tr:nth-child(even) {{ background:var(--wash); }}
    .notice {{ padding:12px 14px; background:#EEF4F8; border-left:4px solid var(--blue); color:#30475E; }}
    .risk-badge {{ white-space: nowrap; }}
    footer {{ margin-top:32px; padding-top:12px; border-top:1px solid var(--line); color:var(--muted); font-size:10px; }}
    @media print {{ body {{ background:#fff; }} main {{ margin:0; max-width:none; box-shadow:none; padding:18mm 14mm; }} thead {{ display:table-header-group; }} tr {{ break-inside:avoid; }} }}
    </style></head><body><main>
    <header class="brand">
      <svg viewBox="0 0 48 56" role="img" aria-label="Shield"><path fill="#123A63" d="M24 1 45 10l-4 27c-2 9-9 15-17 19C16 52 9 46 7 37L3 10 24 1Z"/><path fill="none" stroke="#4CA6D8" stroke-width="2.5" d="M24 10v35M12 22h24"/></svg>
      <div><div class="brand-name">{html.escape(REPORT_BRAND)}</div><div class="report-name">{html.escape(REPORT_TITLE)}</div></div>
    </header>
    <div class="classification">{html.escape(REPORT_CLASSIFICATION)} · Scan {html.escape(report.scan_id)}</div>
    <h1>{html.escape(REPORT_TITLE)}</h1>
    <h2>Summary</h2>
    <table><tr><th>Total Persistence Items</th><th>Critical Findings</th><th>High Findings</th><th>Scanner Coverage Rows</th><th>Last Scan</th></tr>
    <tr><td>{len(report.items)}</td><td>{critical}</td><td>{high}</td><td>{len(report.coverage)}</td><td>{html.escape(report.completed_at)}</td></tr></table>
    <p>Posture score: <strong>{report.posture_score}</strong></p>
    <p class="notice">This report inventories locally observed persistence mechanisms. Findings require analyst validation and do not, by themselves, prove malicious activity. Collection coverage: <strong>{_coverage_status(report)}</strong>.</p>
    <h2>Persistence Mechanism Breakdown</h2>
    <table><tr><th>Mechanism</th><th>Items</th><th>Findings</th><th>Highest Risk Score</th></tr>{mechanism_rows}</table>
    <h2>Top Persistence Risks</h2>
    <table><tr><th>Rank</th><th>Severity</th><th>Item</th><th>Mechanism</th><th>Risk Reason</th><th>Action</th></tr>{top_rows}</table>
    <h2>Complete Persistence Inventory</h2>
    <table><tr><th>Risk</th><th>Risk Score</th><th>Trust</th><th>Trust Score</th><th>Baseline</th><th>Mechanism</th><th>Label</th><th>Path</th><th>Target</th><th>Loaded</th><th>Disabled</th><th>Owner</th><th>Permissions</th><th>Signature</th></tr>{inventory_rows}</table>
    <h2>Persistence Findings</h2>
    <table><tr><th>Severity</th><th>Risk</th><th>Confidence</th><th>Mechanism</th><th>Name / Label</th><th>Target Path</th><th>Why Flagged</th><th>Recommended Action</th><th>MITRE</th></tr>{finding_rows}</table>
    <h2>Coverage</h2>
    <table><tr><th>Scanner</th><th>Rating</th><th>Items</th><th>Findings</th><th>Why It Passed / Failed</th><th>How to Reach or Retain Pass</th></tr>{coverage_rows}</table>
    <h2>Incident Reporting and Evidence Handling</h2>
    <p>Preserve original evidence and do not delete suspicious persistence during triage. Record the device, reporter, UTC time, business impact, and incident number. Hash evidence with SHA-256, analyze a verified copy, document transfers, and report critical findings through the approved incident-response channel.</p>
    <h2>Limitations</h2>
    <p>Read-only scan. Permission-limited locations are reported as partial coverage. Static report: no scripts, macros, formulas, external relationships, or embedded executables.</p>
    <footer>{html.escape(REPORT_BRAND)} · {html.escape(REPORT_CLASSIFICATION)} · Generated from MSAA Persistence Intelligence</footer>
    </main></body></html>
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path

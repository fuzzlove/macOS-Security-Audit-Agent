"""Sanitized operator diagnostics and multi-format health exports."""

from __future__ import annotations

import html
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .persistence import SensorHealthStore


def _xml_text(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _docx_bytes(payload: dict[str, Any], sensors: list[dict[str, Any]]) -> bytes:
    """Build a minimal standards-compliant OOXML document without native dependencies."""
    def paragraph(text: Any, *, bold: bool = False) -> str:
        run = f"<w:r>{'<w:rPr><w:b/></w:rPr>' if bold else ''}<w:t xml:space=\"preserve\">{_xml_text(text)}</w:t></w:r>"
        return f"<w:p>{run}</w:p>"

    def cell(text: Any, *, bold: bool = False) -> str:
        return f"<w:tc><w:tcPr/><w:p><w:r>{'<w:rPr><w:b/></w:rPr>' if bold else ''}<w:t>{_xml_text(text)}</w:t></w:r></w:p></w:tc>"

    headers = ("Sensor", "State", "Score", "Reason Code", "Explanation")
    rows = ["<w:tr>" + "".join(cell(value, bold=True) for value in headers) + "</w:tr>"]
    for item in sensors:
        values = (item.get("sensor_id", ""), item.get("state", ""), item.get("health_score", ""), item.get("reason_code", ""), item.get("reason", ""))
        rows.append("<w:tr>" + "".join(cell(value) for value in values) + "</w:tr>")
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
        + paragraph("MSAA Sensor Health Diagnostics", bold=True)
        + paragraph(f"Overall health: {payload.get('report', {}).get('overall_health', 'UNKNOWN')}")
        + paragraph(f"Generated: {payload.get('generated_at', '')}")
        + '<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>' + "".join(rows) + "</w:tbl>"
        + paragraph(payload.get("privacy", ""))
        + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
        + "</w:body></w:document>"
    )
    content_types = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
    relationships = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)
    return output.getvalue()


def diagnostics_payload(store: SensorHealthStore, report: dict[str, Any], *, history_limit: int = 200) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "bundle_type": "msaa_sensor_health_diagnostics",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "report": report,
        "recent_transitions": store.history(limit=history_limit),
        "dependency_states": store.dependencies(),
        "recovery_history": store.recoveries(limit=history_limit),
        "privacy": "Sanitized functional-health metadata only; credentials, tokens, private keys, and arbitrary event contents are excluded.",
    }


def _secure_write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return path


def export_diagnostics(payload: dict[str, Any], destination: Path) -> Path:
    suffix = destination.suffix.lower()
    if suffix == ".json":
        return _secure_write(destination, (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode())
    sensors = list(payload.get("report", {}).get("sensors", []))
    if suffix in {".html", ".htm"}:
        rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in (
                item.get("sensor_id", ""), item.get("state", ""), item.get("health_score", ""),
                item.get("reason_code", ""), item.get("reason", ""),
            )) + "</tr>" for item in sensors
        )
        body = f"""<!doctype html><html><head><meta charset=\"utf-8\"><title>MSAA Sensor Health Diagnostics</title>
        <style>body{{font-family:-apple-system,sans-serif;margin:32px;color:#142033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd5e0;padding:8px;text-align:left}}th{{background:#edf2f7}}</style></head>
        <body><h1>MSAA Sensor Health Diagnostics</h1><p>Generated: {html.escape(str(payload.get('generated_at','')))}</p>
        <p>Overall: <strong>{html.escape(str(payload.get('report',{}).get('overall_health','UNKNOWN')))}</strong></p>
        <table><thead><tr><th>Sensor</th><th>State</th><th>Score</th><th>Reason Code</th><th>Explanation</th></tr></thead><tbody>{rows}</tbody></table>
        <p>{html.escape(str(payload.get('privacy','')))}</p></body></html>"""
        return _secure_write(destination, body.encode("utf-8"))
    if suffix == ".docx":
        return _secure_write(destination, _docx_bytes(payload, sensors))
    if suffix == ".xlsx":
        from openpyxl import Workbook

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Sensor Health"
        sheet.append(["Sensor", "State", "Score", "Reason Code", "Explanation"])
        for item in sensors:
            sheet.append([item.get("sensor_id", ""), item.get("state", ""), item.get("health_score", ""), item.get("reason_code", ""), item.get("reason", "")])
        coverage = workbook.create_sheet("Coverage")
        coverage.append(["Capability", "Coverage", "Reason", "Fallback"])
        for item in payload.get("report", {}).get("coverage", []):
            coverage.append([item.get("capability_id", ""), item.get("coverage", ""), item.get("reason", ""), item.get("fallback", "")])
        destination.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(destination)
        os.chmod(destination, 0o600)
        return destination
    raise ValueError("Sensor diagnostics format must be .json, .html, .docx, or .xlsx")


__all__ = ["diagnostics_payload", "export_diagnostics"]

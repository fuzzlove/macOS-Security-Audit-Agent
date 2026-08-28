from __future__ import annotations

import csv
import html
import json
import os
from collections.abc import Iterable
from pathlib import Path

from mac_audit_agent.models import utc_now_iso

from .models import CredentialFinding

HEADERS = (
    "Finding ID", "Status", "Severity", "Detected At", "Target", "Product", "Category",
    "Path", "CPE", "Username", "Password", "Recommendation",
)


def _rows(findings: Iterable[CredentialFinding]) -> list[list[str]]:
    return [[
        item.finding_id, item.status, item.severity, item.detected_at, item.target_url,
        item.product, item.category, item.path, item.cpe, item.username, item.password,
        item.recommendation,
    ] for item in findings]


def export_credential_findings(findings: Iterable[CredentialFinding], destination: Path) -> Path:
    destination = Path(destination)
    rows = _rows(findings)
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = destination.suffix.lower()
    if suffix == ".json":
        payload = {
            "schema_version": "1.0", "report_type": "MSAA_DEFAULT_CREDENTIAL_REMEDIATION",
            "exported_at": utc_now_iso(),
            "sensitivity": "HIGHLY SENSITIVE — PLAINTEXT CREDENTIALS",
            "qualification": "Use only for authorized remediation. Rotate every listed credential and protect or securely delete this export afterward.",
            "findings": [dict(zip(HEADERS, row)) for row in rows],
        }
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif suffix == ".csv":
        with destination.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(HEADERS)
            writer.writerows(rows)
    elif suffix == ".html":
        body = "".join("<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in row) + "</tr>" for row in rows)
        destination.write_text(
            "<!doctype html><html><head><meta charset='utf-8'><title>Default Credential Remediation</title>"
            "<style>body{font-family:-apple-system,sans-serif;margin:28px}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #bbb;padding:7px;text-align:left;vertical-align:top}.warning{background:#fee2e2;padding:12px}</style>"
            "</head><body><h1>Default Credential Remediation</h1>"
            "<p class='warning'><strong>Highly sensitive:</strong> This report contains plaintext credentials. Rotate them immediately, restrict access, and securely delete the report when remediation evidence is complete.</p>"
            "<table><thead><tr>" + "".join(f"<th>{html.escape(value)}</th>" for value in HEADERS) + "</tr></thead><tbody>" + body + "</tbody></table>"
            "<p>An accepted default credential proves that credential worked at collection time; it does not prove compromise or prior use.</p></body></html>",
            encoding="utf-8",
        )
    elif suffix == ".txt":
        lines = ["MSAA DEFAULT CREDENTIAL REMEDIATION", "HIGHLY SENSITIVE — PLAINTEXT CREDENTIALS", ""]
        for row in rows:
            lines.extend(f"{key}: {value}" for key, value in zip(HEADERS, row))
            lines.append("")
        destination.write_text("\n".join(lines), encoding="utf-8")
    else:
        raise ValueError("Default credential exports support .json, .csv, .html, and .txt")
    os.chmod(destination, 0o600)
    return destination


__all__ = ["export_credential_findings"]

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report

from .findings import CodeReviewReport
from .language_rules import supported_language_names


def export_json(report: CodeReviewReport, destination: Path) -> Path:
    destination.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def export_csv(report: CodeReviewReport, destination: Path) -> Path:
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Finding ID", "Severity", "CVSS", "Language", "CWE", "Title", "File", "Line", "Confidence", "Remediation"])
        for finding in report.findings:
            writer.writerow([
                finding.finding_id, finding.severity, finding.cvss_score, finding.language, finding.cwe,
                finding.title, finding.affected_file, finding.line, finding.confidence,
                "; ".join(finding.remediation.get("immediate", ())),
            ])
    return destination


def export_html(report: CodeReviewReport, destination: Path) -> Path:
    counts = report.counts()
    highest = next((name for name in ("critical", "high", "medium", "low") if counts.get(name)), "none")
    findings = []
    for finding in report.findings:
        references = "".join(
            f'<li><a href="{html.escape(item["url"])}">{html.escape(item["source"])}</a></li>'
            for item in finding.references
        )
        findings.append(
            f"<section><h2>{html.escape(finding.severity.upper())}: {html.escape(finding.title)}</h2>"
            f"<p><strong>{html.escape(finding.finding_id)}</strong> — {html.escape(finding.affected_file)}:{finding.line}</p>"
            f"<p><strong>{html.escape(finding.cwe)}</strong> | {html.escape(finding.language)} | CVSS {finding.cvss_score} "
            f"<code>{html.escape(finding.cvss_vector)}</code></p>"
            f"<h3>Why this matters</h3><p>{html.escape(finding.analyst_explanation)}</p>"
            f"<h3>Detection reason</h3><p>{html.escape(finding.detection_reason)}</p>"
            f"<h3>Evidence</h3><pre>{html.escape(finding.evidence)}</pre>"
            f"<h3>Impact</h3><pre>{html.escape(json.dumps(finding.impact, indent=2))}</pre>"
            f"<h3>Remediation</h3><pre>{html.escape(json.dumps(finding.remediation, indent=2))}</pre>"
            f"<h3>Official references</h3><ul>{references}</ul></section>"
        )
    document = (
        "<!doctype html><html><head><meta charset='utf-8'><title>MSAA Code Review</title>"
        "<style>body{font-family:-apple-system,sans-serif;max-width:1100px;margin:auto;padding:24px}"
        "section{border:1px solid #ccc;border-radius:8px;padding:16px;margin:16px 0}pre{white-space:pre-wrap}</style></head><body>"
        f"<h1>Multi-Language Security Review Summary</h1><p>Supported source languages: {html.escape(', '.join(supported_language_names()))}</p><p>Risk rating: <strong>{highest.upper()}</strong></p>"
        f"<p>Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}</p>"
        + "".join(findings) + "</body></html>"
    )
    destination.write_text(document, encoding="utf-8")
    return destination


def export_professional(report: CodeReviewReport, destination: Path) -> Path:
    counts = report.counts()
    rows = tuple(
        (
            finding.finding_id, finding.severity.upper(), finding.cvss_score, finding.confidence,
            finding.language, finding.cwe, finding.title, finding.affected_file, finding.line,
            finding.analyst_explanation, finding.detection_reason, finding.evidence,
            "; ".join(finding.remediation.get("immediate", ())),
            "; ".join(item.get("url", "") for item in finding.references),
        )
        for finding in report.findings
    )
    return write_professional_report(
        destination,
        title="MSAA Multi-Language Security Review",
        sections=(ReportSection("Executive Summary", (
            f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}",
            "Supported source languages: " + ", ".join(supported_language_names()),
        )),),
        tables=(ReportTable("Findings", (
            "Finding ID", "Severity", "CVSS", "Confidence", "Language", "CWE", "Title", "File", "Line",
            "Why This Matters", "Detection Reason", "Evidence", "Suggested Fix", "Official References",
        ), rows),),
        qualification="Static analysis supports authorized analyst review. A finding does not by itself prove exploitability; validate it in the affected context.",
    )


__all__ = ["export_csv", "export_html", "export_json", "export_professional"]

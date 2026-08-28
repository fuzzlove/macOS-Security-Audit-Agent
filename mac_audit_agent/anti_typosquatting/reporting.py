from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report

from .models import AnalysisRun


def _spreadsheet_safe(value: Any) -> str:
    text = str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def export_json(run: AnalysisRun, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(run.to_dict(), indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    return path


def export_csv(run: AnalysisRun, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["candidate_name", "ascii_name", "categories", "risk_band", "attacker_use_assumption", "name_closeness", "human_typo_likelihood", "impersonation_similarity", "defensive_registration_priority", "investigation_priority", "lookup_status", "generation_reason", "recommended_action", "registration_guidance"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for candidate in run.candidates:
            row = {
                "candidate_name": candidate.display_name,
                "ascii_name": candidate.ascii_name,
                "categories": "; ".join(candidate.categories),
                "risk_band": candidate.risk_band,
                "attacker_use_assumption": candidate.attacker_use_assumption.total,
                "name_closeness": candidate.name_closeness.total,
                "human_typo_likelihood": candidate.human_typo.total,
                "impersonation_similarity": candidate.impersonation.total,
                "defensive_registration_priority": candidate.defensive_registration.total,
                "investigation_priority": candidate.investigation.total,
                "lookup_status": candidate.lookup_status,
                "generation_reason": "; ".join(reason.explanation for reason in candidate.reasons),
                "recommended_action": candidate.recommended_action,
                "registration_guidance": candidate.registration_guidance,
            }
            writer.writerow({key: _spreadsheet_safe(value) for key, value in row.items()})
    return path


def export_html(run: AnalysisRun, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for candidate in run.candidates:
        values = [candidate.display_name, candidate.ascii_name, candidate.risk_band.upper(), candidate.attacker_use_assumption.total, candidate.name_closeness.total, ", ".join(candidate.categories), candidate.human_typo.total, candidate.impersonation.total, candidate.lookup_status, candidate.registration_guidance, "; ".join(reason.explanation for reason in candidate.reasons)]
        rows.append("<tr>" + "".join("<td>%s</td>" % html.escape(str(value), quote=True) for value in values) + "</tr>")
    document = """<!doctype html><meta charset='utf-8'><title>MSAA Anti-Typosquatting Analysis</title>
<h1>Anti-Typosquatting Analysis</h1><p>Protected asset: <code>%s</code></p>
<p>Local-first defensive analysis. Existing names are not automatically malicious. Missing registration data does not guarantee purchase availability. MSAA does not provide legal advice.</p>
<table><thead><tr><th>Candidate</th><th>ASCII/Punycode</th><th>Risk Band</th><th>Attacker-use Assumption</th><th>Name Closeness</th><th>Categories</th><th>Human Typo</th><th>Impersonation</th><th>Lookup</th><th>Registration Guidance</th><th>Reasons</th></tr></thead><tbody>%s</tbody></table>
<h2>Data versions</h2><pre>%s</pre>""" % (html.escape(run.asset.canonical_name), "".join(rows), html.escape(json.dumps(run.data_versions, indent=2, sort_keys=True)))
    path.write_text(document, encoding="utf-8")
    return path


def export_professional(run: AnalysisRun, path: Path) -> Path:
    rows = tuple(
        (
            candidate.display_name, candidate.ascii_name, ", ".join(candidate.categories),
            candidate.risk_band.upper(), candidate.attacker_use_assumption.total, candidate.name_closeness.total,
            candidate.human_typo.total, candidate.impersonation.total,
            candidate.defensive_registration.total, candidate.investigation.total,
            candidate.lookup_status, "; ".join(reason.explanation for reason in candidate.reasons),
            candidate.recommended_action, candidate.registration_guidance,
        )
        for candidate in run.candidates
    )
    return write_professional_report(
        path,
        title="MSAA Anti-Typosquatting Analysis",
        sections=(ReportSection("Protected Asset", (run.asset.canonical_name,)),),
        tables=(ReportTable("Candidate Review", (
            "Candidate", "ASCII / Punycode", "Categories", "Risk Band", "Attacker-use Assumption", "Name Closeness", "Human Typo", "Impersonation",
            "Defensive Registration", "Investigation", "Lookup", "Reasons", "Recommended Action",
            "Registration Guidance",
        ), rows),),
        qualification="Local-first defensive analysis. Similarity is not proof of malicious intent, and missing registration data does not guarantee availability.",
    )


__all__ = ["export_json", "export_csv", "export_html", "export_professional", "_spreadsheet_safe"]

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any


CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def default_kev_cache_path() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "cisa_kev_catalog.json"


def load_kev_catalog(path: Path | None = None) -> dict[str, Any]:
    candidate = path or default_kev_cache_path()
    if not candidate.exists():
        return {"available": False, "message": "CISA KEV catalog unavailable in local cache.", "vulnerabilities": []}
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "message": f"CISA KEV cache unreadable: {exc}", "vulnerabilities": []}
    vulnerabilities = payload.get("vulnerabilities", payload if isinstance(payload, list) else [])
    return {"available": True, "source_url": CISA_KEV_URL, "catalog": payload, "vulnerabilities": vulnerabilities if isinstance(vulnerabilities, list) else []}


def _record_for_cve(cve_id: str, catalog: dict[str, Any] | None = None) -> dict[str, Any] | None:
    payload = catalog or load_kev_catalog()
    for item in payload.get("vulnerabilities", []):
        if isinstance(item, dict) and str(item.get("cveID", item.get("cve_id", ""))).upper() == cve_id.upper():
            return item
    return None


def is_cve_in_kev(cve_id: str, catalog: dict[str, Any] | None = None) -> bool:
    return _record_for_cve(cve_id, catalog) is not None


def get_kev_action(cve_id: str, catalog: dict[str, Any] | None = None) -> str:
    record = _record_for_cve(cve_id, catalog)
    return str(record.get("requiredAction", record.get("required_action", ""))) if record else ""


def get_kev_due_date(cve_id: str, catalog: dict[str, Any] | None = None) -> str:
    record = _record_for_cve(cve_id, catalog)
    return str(record.get("dueDate", record.get("due_date", ""))) if record else ""


def generate_kev_priority(finding: dict[str, Any]) -> dict[str, Any]:
    cve_ids = [str(item).upper() for item in finding.get("cve_ids", []) if str(item).upper().startswith("CVE-")]
    if not cve_ids and finding.get("cve_refs"):
        cve_ids = [str(item).upper() for item in finding.get("cve_refs", []) if str(item).upper().startswith("CVE-")]
    catalog = load_kev_catalog()
    matches = []
    for cve_id in cve_ids:
        record = _record_for_cve(cve_id, catalog)
        if record:
            due = get_kev_due_date(cve_id, catalog)
            past_due = False
            try:
                past_due = bool(due) and date.fromisoformat(due) < date.today()
            except ValueError:
                past_due = False
            matches.append(
                {
                    "cve_id": cve_id,
                    "known_exploited": True,
                    "priority": "urgent",
                    "required_action": get_kev_action(cve_id, catalog),
                    "due_date": due,
                    "past_due_for_kev_style_review": past_due,
                    "vendor_project": record.get("vendorProject", ""),
                    "product": record.get("product", ""),
                    "notes": "CISA KEV indicates known exploitation of the vulnerability, not confirmed compromise of this Mac.",
                }
            )
    return {
        "catalog_available": bool(catalog.get("available")),
        "source_url": CISA_KEV_URL,
        "matches": matches,
        "known_exploited": bool(matches),
        "message": "" if matches else "CVE not found in local CISA KEV cache or KEV cache unavailable.",
        "scope_note": "CISA KEV is still useful for prioritization but may not impose a direct obligation unless your organization is in scope.",
    }

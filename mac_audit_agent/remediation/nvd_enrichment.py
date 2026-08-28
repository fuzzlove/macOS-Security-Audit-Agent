from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mac_audit_agent.remediation.models import SourceMapping


NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
NVD_API_URL = "https://nvd.nist.gov/developers/vulnerabilities"


def default_nvd_cache_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "nvd_cache"


def enrich_cve(cve_id: str, cache_dir: Path | None = None) -> dict[str, Any]:
    normalized = cve_id.upper().strip()
    cache = cache_dir or default_nvd_cache_dir()
    for candidate in (cache / f"{normalized}.json", cache / f"{normalized.lower()}.json"):
        if candidate.exists():
            try:
                record = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return _unavailable(normalized, f"NVD cache unreadable: {exc}")
            return {"available": True, "source": "NVD local cache", "retrieved_at": record.get("retrieved_at", ""), "cve_id": normalized, "record": record}
    return _unavailable(normalized, "NVD enrichment unavailable; use vendor advisory and local evidence.")


def _unavailable(cve_id: str, reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "source": "NVD",
        "source_url": NVD_CVE_URL.format(cve_id=cve_id),
        "cve_id": cve_id,
        "message": reason,
    }


def lookup_cve_from_product_version(product: str, version: str, cache_dir: Path | None = None) -> list[dict[str, Any]]:
    if not product or not version:
        return []
    cache = cache_dir or default_nvd_cache_dir()
    index = cache / "product_version_index.json"
    if not index.exists():
        return []
    try:
        payload = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    key = f"{product.lower()}::{version.lower()}"
    cves = payload.get(key, [])
    return [enrich_cve(str(cve), cache_dir=cache) for cve in cves if str(cve).upper().startswith("CVE-")]


def get_cvss_summary(cve_record: dict[str, Any]) -> dict[str, Any]:
    record = cve_record.get("record", cve_record) if isinstance(cve_record, dict) else {}
    metrics = record.get("metrics") or record.get("impact") or {}
    if not isinstance(metrics, dict):
        return {"available": False}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values:
            cvss_data = values[0].get("cvssData", {})
            return {
                "available": True,
                "version": cvss_data.get("version", key),
                "base_score": cvss_data.get("baseScore"),
                "base_severity": values[0].get("baseSeverity") or cvss_data.get("baseSeverity"),
                "vector": cvss_data.get("vectorString"),
            }
    return {"available": False}


def get_vendor_references(cve_record: dict[str, Any]) -> list[dict[str, str]]:
    record = cve_record.get("record", cve_record) if isinstance(cve_record, dict) else {}
    refs = record.get("references") or record.get("cve", {}).get("references", {})
    data = refs.get("referenceData", refs if isinstance(refs, list) else [])
    results = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict):
            results.append({"url": str(item.get("url", "")), "source": str(item.get("source", "")), "tags": ", ".join(str(tag) for tag in item.get("tags", []))})
    return [item for item in results if item["url"]]


def get_cwe_summary(cve_record: dict[str, Any]) -> list[str]:
    record = cve_record.get("record", cve_record) if isinstance(cve_record, dict) else {}
    weaknesses = record.get("weaknesses") or record.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
    values: list[str] = []
    for item in weaknesses if isinstance(weaknesses, list) else []:
        descriptions = item.get("description", []) if isinstance(item, dict) else []
        for desc in descriptions:
            value = desc.get("value") if isinstance(desc, dict) else ""
            if value:
                values.append(str(value))
    return sorted(set(values))


def generate_cve_recommended_fix(cve_record: dict[str, Any], local_context: dict[str, Any] | None = None) -> dict[str, Any]:
    cve_id = str(cve_record.get("cve_id", "")).upper()
    local_context = local_context or {}
    cvss = get_cvss_summary(cve_record)
    references = get_vendor_references(cve_record)
    return {
        "summary": f"Review and remediate {cve_id} for the locally detected component.",
        "recommended_fix": "Update or patch the affected software according to the vendor advisory. If no patch is available, apply the vendor mitigation or remove the affected component.",
        "validation_steps": [
            "Confirm the installed product and version no longer match the affected version range.",
            "Re-run the MSAA scan and retain remediation evidence.",
        ],
        "cvss": cvss,
        "vendor_references": references,
        "cwe": get_cwe_summary(cve_record),
        "local_asset": {
            "product": local_context.get("detected_product") or local_context.get("product", ""),
            "version": local_context.get("detected_version") or local_context.get("version", ""),
            "path": local_context.get("related_path", ""),
        },
        "source_mapping": SourceMapping(
            source_type="NVD",
            source_id=cve_id,
            source_url=NVD_CVE_URL.format(cve_id=cve_id),
            source_version="NVD CVE detail",
            mapping_confidence="direct" if cve_id else "manual_review_required",
            notes="NVD provides CVE/CPE/CVSS enrichment when available; local applicability still requires version validation.",
        ).to_dict(),
    }

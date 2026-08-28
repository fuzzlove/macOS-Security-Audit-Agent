from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.professional_report import ReportSection, ReportTable, write_professional_report


@dataclass(frozen=True)
class DNSAssuranceResult:
    observed_servers: tuple[str, ...]
    approved_servers: tuple[str, ...]
    unapproved_servers: tuple[str, ...]
    missing_approved_servers: tuple[str, ...]
    threat_matches: tuple[dict[str, str], ...]
    evidence_state: str
    client_validation_state: str
    status: str
    collected_at: str
    intelligence_status: str
    explanation: str

    def to_dict(self) -> dict[str, Any]: return asdict(self)


def normalize_dns_servers(values) -> tuple[str, ...]:
    normalized = []
    for value in values or []:
        try: candidate = str(ipaddress.ip_address(str(value).strip()))
        except ValueError: continue
        if candidate not in normalized: normalized.append(candidate)
    return tuple(normalized)


def load_dns_threat_intelligence(path: Path, *, max_bytes: int = 2 * 1024 * 1024) -> tuple[dict[str, dict[str, str]], str]:
    if not path.is_file(): return {}, "not configured"
    raw = path.read_bytes()
    if len(raw) > max_bytes: raise ValueError("DNS intelligence file exceeds the size limit.")
    try: payload = json.loads(raw)
    except json.JSONDecodeError as exc: raise ValueError("DNS intelligence file is invalid JSON.") from exc
    if payload.get("schema_version") != "1.0" or not payload.get("source_name") or not payload.get("retrieved_at") or not isinstance(payload.get("indicators"), list): raise ValueError("DNS intelligence provenance or schema is incomplete.")
    records = {}
    for item in payload["indicators"][:10000]:
        if not isinstance(item, dict): continue
        address = normalize_dns_servers([item.get("address")])
        if not address: continue
        records[address[0]] = {"source_name":str(payload["source_name"])[:200],"source_url":str(payload.get("source_url", ""))[:500],"retrieved_at":str(payload["retrieved_at"])[:100],"reason":str(item.get("reason", "Reported malicious DNS infrastructure"))[:1000],"reference":str(item.get("reference", ""))[:500],"content_sha256":hashlib.sha256(raw).hexdigest()}
    return records, f"loaded {len(records)} provenance-backed indicators from {payload['source_name']}"


def assess_dns_configuration(observed, approved, *, evidence_collected: bool, client_validated: bool, intelligence: dict[str, dict[str, str]] | None = None, intelligence_status: str = "not configured", collected_at: str = "") -> DNSAssuranceResult:
    observed_values=normalize_dns_servers(observed); approved_values=normalize_dns_servers(approved); threat_intel=intelligence or {}; matches=tuple({"address":address,**threat_intel[address]} for address in observed_values if address in threat_intel); unapproved=tuple(value for value in observed_values if value not in approved_values); missing=tuple(value for value in approved_values if value not in observed_values)
    evidence_state="collected" if evidence_collected else "not collected"; validation="validated by client" if client_validated else "pending client validation"
    if not evidence_collected or not observed_values: status="not collected"
    elif matches: status="red flag"
    elif unapproved or missing: status="concern"
    elif not client_validated: status="concern"
    else: status="validated"
    explanation = "Observed DNS configuration requires client scope validation." if status == "concern" else "A configured threat-intelligence indicator matched an observed resolver; notify the client immediately and independently validate the source and device state." if status == "red flag" else "Observed DNS servers match the client-approved list." if status == "validated" else "DNS evidence has not been collected."
    return DNSAssuranceResult(observed_values,approved_values,unapproved,missing,matches,evidence_state,validation,status,collected_at or datetime.now(timezone.utc).isoformat(),intelligence_status,explanation)


def export_dns_report(result: DNSAssuranceResult, output: Path) -> Path:
    payload={"schema_version":"1.0","report_type":"MSAA_DNS_CONFIGURATION_ASSURANCE","result":result.to_dict(),"qualification":"Client approval is an organizational assertion. Threat matches require independent source validation and do not alone prove compromise."}
    if output.suffix.lower()==".json": output.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    elif output.suffix.lower()==".html":
        import html
        rows="".join(f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(json.dumps(value) if isinstance(value,(list,tuple,dict)) else str(value))}</td></tr>" for key,value in result.to_dict().items()); output.write_text(f"<!doctype html><meta charset='utf-8'><title>DNS Configuration Assurance</title><h1>DNS Configuration Assurance</h1><table border='1'>{rows}</table><p>{html.escape(payload['qualification'])}</p>",encoding="utf-8")
    elif output.suffix.lower() in {".docx", ".xlsx"}:
        write_professional_report(
            output,
            title="MSAA DNS Configuration Assurance",
            sections=(ReportSection("Assessment", (result.explanation,)),),
            tables=(ReportTable("DNS Configuration", ("Field", "Value"), tuple(
                (str(key).replace("_", " ").title(), json.dumps(value) if isinstance(value, (list, tuple, dict)) else value)
                for key, value in result.to_dict().items()
            )),),
            qualification=payload["qualification"],
        )
    else: raise ValueError("DNS reports support .json, .html, .docx, and .xlsx")
    return output

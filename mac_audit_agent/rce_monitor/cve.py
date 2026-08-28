from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from packaging.version import InvalidVersion, Version

from .models import CVECorrelation, utc_now
from .repository import RCERepository

CVE_ID = re.compile(r"^CVE-(19|20)\d{2}-\d{4,}$")


class VulnerabilityProvider(Protocol):
    name: str
    def import_file(self, path: Path, repository: RCERepository, freshness_hours: int) -> int: ...


def compare_versions(left: str, right: str) -> int:
    try:
        a, b = Version(left), Version(right)
    except InvalidVersion as exc:
        raise ValueError("unparseable ecosystem version") from exc
    return (a > b) - (a < b)


def version_in_range(version: str, constraints: dict[str, str]) -> bool:
    if "introduced" in constraints and compare_versions(version, constraints["introduced"]) < 0: return False
    if "fixed" in constraints and compare_versions(version, constraints["fixed"]) >= 0: return False
    if "last_affected" in constraints and compare_versions(version, constraints["last_affected"]) > 0: return False
    return True


@dataclass
class LocalJSONCVEProvider:
    """Offline, bounded provider for administrator-approved normalized CVE data."""
    name: str = "approved-local-json"
    parser_version: str = "1.0"
    max_bytes: int = 32 * 1024 * 1024

    def import_file(self, path: Path, repository: RCERepository, freshness_hours: int = 168) -> int:
        if path.stat().st_size > self.max_bytes: raise ValueError("CVE input exceeds configured maximum")
        raw = path.read_bytes(); payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0" or not isinstance(payload.get("records"), list):
            raise ValueError("unsupported normalized CVE input")
        retrieved = str(payload.get("retrieved_at") or utc_now())
        expires = (datetime.fromisoformat(retrieved.replace("Z", "+00:00")) + timedelta(hours=freshness_hours)).isoformat()
        count = 0
        with repository.conn:
            for item in payload["records"]:
                if not isinstance(item, dict): raise ValueError("CVE record must be an object")
                cve_id = str(item.get("cve_id", "")).upper()
                if not CVE_ID.fullmatch(cve_id): raise ValueError("unverified CVE identifier")
                if not item.get("product") or not item.get("summary") or not isinstance(item.get("affected"), list):
                    raise ValueError("CVE record missing validated product, summary, or affected ranges")
                canonical = json.dumps(item,sort_keys=True,separators=(",", ":")); digest=hashlib.sha256(canonical.encode()).hexdigest()
                repository.conn.execute("INSERT OR REPLACE INTO rce_cve_records(cve_id,source_name,source_record_id,retrieved_at,published_at,last_modified_at,format_version,content_hash,parser_version,validation_status,expires_at,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (cve_id,str(payload.get("source_name",self.name)),str(item.get("source_record_id",cve_id)),retrieved,str(item.get("published_at","")),str(item.get("last_modified_at","")),"1.0",digest,self.parser_version,"VALIDATED_LOCAL_IMPORT",expires,canonical))
                count += 1
        return count


class CVECorrelator:
    def __init__(self, repository: RCERepository) -> None: self.repository=repository

    def get(self,cve_id:str)->dict[str,Any]|None:
        if not CVE_ID.fullmatch(cve_id.upper()): return None
        row=self.repository.conn.execute("SELECT * FROM rce_cve_records WHERE cve_id=?",(cve_id.upper(),)).fetchone()
        if not row:return None
        result=json.loads(row["payload_json"]); result["source_name"]=row["source_name"]; result["retrieved_at"]=row["retrieved_at"]; result["content_hash"]=row["content_hash"]; result["stale"]=datetime.fromisoformat(row["expires_at"].replace("Z","+00:00")) < datetime.now(timezone.utc)
        return result

    def exposure(self, *, cve_id:str, product:str, version:str, platform_name:str="macOS", backport_fixed:bool=False, mitigated:bool=False)->CVECorrelation:
        record=self.get(cve_id)
        if record is None: raise ValueError("CVE identifier is not present in the approved local store")
        product_match=re.sub(r"\W+","",product.lower())==re.sub(r"\W+","",str(record["product"]).lower())
        affected=any(version_in_range(version,dict(rng)) for rng in record["affected"]) if product_match and version else False
        matching=["approved local CVE record"]
        nonmatching=[]; unknown=[]
        if product_match: matching.append("exact normalized product identity")
        else: nonmatching.append("observed product does not match affected product")
        if affected: matching.append("ecosystem-parsed version falls within an affected range")
        elif version: nonmatching.append("observed version is outside affected ranges")
        else: unknown.append("installed version unavailable")
        if backport_fixed: nonmatching.append("vendor backport metadata indicates the fix is present")
        if mitigated: nonmatching.append("required exposure condition is mitigated or unreachable")
        exact=product_match and affected and not backport_fixed and not mitigated
        relationship="EXACT_PRODUCT_VERSION_EXPOSURE" if exact else "CVE_MATCH_REJECTED" if nonmatching else "INSUFFICIENT_EVIDENCE_FOR_CVE_MATCH"
        conclusion=f"The host appears exposed to {cve_id.upper()}, but exploitation has not been established." if exact else f"The proposed CVE relationship is not supported because {', '.join(nonmatching) or 'available evidence is insufficient'}."
        return CVECorrelation(cve_id=cve_id.upper(),relationship_type=relationship,confidence="high" if exact else "medium",confidence_basis="deterministic product, ecosystem version-range, mitigation, and backport evaluation",source=str(record["source_name"]),source_record_hash=str(record["content_hash"]),source_retrieval_date=str(record["retrieved_at"]),affected_product=str(record["product"]),affected_component=str(record.get("component","")),affected_version_range=json.dumps(record["affected"],sort_keys=True),observed_product=product,observed_version=version,version_match_status="affected" if affected else "not_affected",backport_status="fixed" if backport_fixed else "not_reported",matching_criteria=matching,non_matching_criteria=nonmatching,unknown_criteria=unknown,observed_behavior_summary=f"Local inventory reported {product} {version or 'with unknown version'} on {platform_name}.",cve_behavior_summary=str(record["summary"]),mitigation_summary=str(record.get("mitigation","Not supplied by approved source")),validation_required=["Confirm package provenance and vendor build/revision metadata.","Confirm service reachability and relevant configuration."],conclusion=conclusion)

    def behavior_similarity(self,cve_id:str,observed_summary:str,matching:list[str],unknown:list[str],similarity_percent:int=0)->CVECorrelation:
        record=self.get(cve_id)
        if record is None: raise ValueError("CVE identifier is not present in the approved local store")
        similarity=max(0,min(int(similarity_percent),100))
        confidence="medium" if similarity >= 70 and len(matching) >= 3 else "low"
        return CVECorrelation(cve_id=cve_id.upper(),relationship_type="BEHAVIORALLY_SIMILAR_TO_CVE",confidence=confidence,confidence_basis="multiple behavior characteristics overlap an approved CVE profile; product/version and vulnerable path still require validation",source=str(record["source_name"]),source_record_hash=str(record["content_hash"]),source_retrieval_date=str(record["retrieved_at"]),affected_product=str(record["product"]),affected_component=str(record.get("component","")),affected_version_range=json.dumps(record["affected"],sort_keys=True),matching_criteria=list(matching),non_matching_criteria=[],unknown_criteria=list(unknown) or ["affected product and version not established"],observed_behavior_summary=observed_summary,cve_behavior_summary=str(record["summary"]),mitigation_summary=str(record.get("mitigation","Not supplied by approved source")),validation_required=["Validate product, version, vulnerable processing path, input vector, and prerequisites."],conclusion=f"The observed behavior is {similarity}% similar to the approved behavior profile for {cve_id.upper()}, but the available evidence does not establish that this CVE was used.",similarity_percent=similarity)

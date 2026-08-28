"""Context-aware threat exposure prioritization for MSAA.

This module correlates existing MSAA evidence.  It is not a vulnerability
scanner and never treats KEV, threat intelligence, or a graph path as proof of
local exploitation or compromise.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
SENSITIVE_KEYS = {"password", "secret", "token", "private_key", "credential", "cookie"}
ASSET_IMPORTANCE = {"standard": 3, "business": 7, "administrator": 11, "developer": 11, "school_administration": 12, "critical_infrastructure": 15}
EXPOSURE_LEVEL = {"local": 2, "user_exposed": 5, "network_accessible": 7, "internet_reachable": 10}


def _canonical(value: Any) -> str: return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
def _hash(value: Any) -> str: return hashlib.sha256(_canonical(value).encode()).hexdigest()
def _now() -> str: return datetime.now(timezone.utc).isoformat()


def _version_tuple(value: str) -> tuple[int, ...] | None:
    text = str(value).strip().lstrip("vV")
    if not text or not re.fullmatch(r"\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?", text): return None
    return tuple(int(item) for item in text.split("-", 1)[0].split("+", 1)[0].split("."))


def version_is_affected(installed: str, *, affected_version: str = "", fixed_version: str = "") -> bool | None:
    current = _version_tuple(installed)
    if current is None: return None
    if fixed_version:
        fixed = _version_tuple(fixed_version)
        if fixed is None: return None
        width = max(len(current), len(fixed)); return current + (0,) * (width - len(current)) < fixed + (0,) * (width - len(fixed))
    spec = str(affected_version).strip()
    if not spec: return None
    match = re.fullmatch(r"(<=|>=|<|>|==)?\s*(.+)", spec)
    target = _version_tuple(match.group(2)) if match else None
    if target is None: return None
    width = max(len(current), len(target)); left = current + (0,) * (width - len(current)); right = target + (0,) * (width - len(target)); op = match.group(1) or "=="
    return {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right, "==": left == right}[op]


@dataclass(frozen=True)
class ExposureAsset:
    asset_id: str
    asset_type: str
    importance: str
    trust_state: str
    security_score: int
    compliance_state: str
    internet_exposure: str
    privileged_user: bool
    evidence_reference: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class ThreatIntelligenceMatch:
    indicator_type: str
    indicator_value: str
    source: str
    timestamp: str
    confidence: str
    reference: str
    status: str

    def to_dict(self) -> dict[str, Any]: return asdict(self)

    def valid(self) -> bool:
        return bool(self.indicator_type and self.indicator_value and self.source and self.reference and self.confidence in {"low", "medium", "high"} and self.timestamp and _parse_time(self.timestamp))


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")); return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError): return None


@dataclass(frozen=True)
class ExposureRecord:
    exposure_id: str
    timestamp: str
    asset_id: str
    risk_category: str
    affected_component: str
    cve_id: str
    mitre_mapping: tuple[str, ...]
    threat_source: tuple[str, ...]
    severity: str
    cvss_score: float | None
    exploit_status: str
    exposure_score: int
    evidence_reference: tuple[str, ...]
    recommendation: str
    status: str
    score_factors: tuple[str, ...]
    risk_explanation: str
    confidence: str
    uncertainty: tuple[str, ...]
    expected_risk_reduction: int
    previous_state: Any = None
    current_state: Any = None

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class ExposureAssessment:
    assessment_id: str
    timestamp: str
    asset: ExposureAsset
    overall_exposure_score: int
    exposures: tuple[ExposureRecord, ...]
    remediation_order: tuple[str, ...]
    score_explanation: tuple[str, ...]
    integrity_hash: str = ""
    qualification: str = "Exposure priority reflects evidence-backed risk context. It does not prove exploitation, compromise, or attacker presence."

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "asset": self.asset.to_dict(), "exposures": [item.to_dict() for item in self.exposures]}


class ThreatExposureManagementEngine:
    def assess(
        self,
        asset: ExposureAsset,
        *,
        software: Iterable[Mapping[str, Any]] = (), vulnerabilities: Iterable[Mapping[str, Any]] = (),
        configuration_findings: Iterable[Mapping[str, Any]] = (), identity_findings: Iterable[Mapping[str, Any]] = (),
        supply_chain_findings: Iterable[Mapping[str, Any]] = (), threat_intelligence: Iterable[ThreatIntelligenceMatch | Mapping[str, Any]] = (),
        posture_graph: Mapping[str, Any] | None = None, timestamp: str | None = None,
    ) -> ExposureAssessment:
        timestamp = timestamp or _now(); intelligence = self._intelligence(threat_intelligence); records: list[ExposureRecord] = []
        software_items = [self._sanitize(dict(item)) for item in software]
        for vulnerability in vulnerabilities:
            record = self._vulnerability(asset, software_items, self._sanitize(dict(vulnerability)), intelligence, posture_graph or {}, timestamp)
            if record: records.append(record)
        records.extend(self._generic(asset, configuration_findings, "configuration", timestamp))
        records.extend(self._generic(asset, identity_findings, "identity", timestamp))
        records.extend(self._generic(asset, supply_chain_findings, "supply_chain", timestamp))
        records.sort(key=lambda item: (-item.exposure_score, item.affected_component, item.exposure_id))
        overall = min(100, round(max((item.exposure_score for item in records), default=0) * .7 + sum(sorted((item.exposure_score for item in records), reverse=True)[1:4]) * .1))
        order = tuple(item.exposure_id for item in records if item.status == "open")
        explanations = tuple(f"{index}. {item.affected_component}: {item.exposure_score}/100; expected reduction {item.expected_risk_reduction}; {item.risk_explanation}" for index, item in enumerate(records, 1)) or ("No evidence-backed exposures were identified from the supplied module outputs.",)
        base = ExposureAssessment(f"exposure-assessment-{uuid4().hex}", timestamp, asset, overall, tuple(records), order, explanations)
        digest = _hash(base.to_dict())
        return ExposureAssessment(**{**base.to_dict(), "asset": asset, "exposures": tuple(records), "remediation_order": order, "score_explanation": explanations, "integrity_hash": digest})

    def _vulnerability(self, asset: ExposureAsset, software: list[dict[str, Any]], vuln: dict[str, Any], intel: tuple[ThreatIntelligenceMatch, ...], graph: Mapping[str, Any], timestamp: str) -> ExposureRecord | None:
        cve = str(vuln.get("cve_id", "")).upper(); product = str(vuln.get("product", "")).strip().lower()
        if not CVE_RE.fullmatch(cve) or not product: return None
        matches = [item for item in software if str(item.get("product", item.get("name", ""))).strip().lower() == product]
        applicable: list[dict[str, Any]] = []
        unknown_versions = False
        for item in matches:
            result = version_is_affected(str(item.get("version", "")), affected_version=str(vuln.get("affected_version", "")), fixed_version=str(vuln.get("fixed_version", "")))
            if result is True: applicable.append(item)
            elif result is None: unknown_versions = True
        if not applicable: return None
        component = str(applicable[0].get("name", applicable[0].get("product", product)))
        refs = set(asset.evidence_reference) | set(self._refs(vuln.get("evidence_reference", []))) | set(self._refs(applicable[0].get("evidence_reference", [])))
        if not refs: return None
        cvss = self._cvss(vuln.get("cvss_score")); factors: list[tuple[str, int]] = [(f"CVSS contribution ({cvss if cvss is not None else 'unknown'})", round((cvss or 0) * 4))]
        relevant_intel = [item for item in intel if item.indicator_type == "cve" and item.indicator_value.upper() == cve]
        kev = [item for item in relevant_intel if item.source.lower() in {"cisa kev", "cisa_kev"} and item.status in {"known_exploited", "confirmed_exploited"}]
        public_exploit = [item for item in relevant_intel if item.status == "public_exploit"]
        active = [item for item in relevant_intel if item.status == "active_exploitation"]
        if kev: factors.append(("CISA KEV confirmed exploitation in the wild", 30))
        if public_exploit: factors.append(("Public exploit availability", 10))
        if active: factors.append(("Sourced active-exploitation reporting", 12))
        factors.append((f"Asset importance ({asset.importance})", ASSET_IMPORTANCE.get(asset.importance, 3)))
        factors.append((f"Exposure ({asset.internet_exposure})", EXPOSURE_LEVEL.get(asset.internet_exposure, 2)))
        if asset.privileged_user: factors.append(("Privileged user context", 7))
        if asset.trust_state == "CONDITIONAL TRUST": factors.append(("Device trust (CONDITIONAL TRUST)", 3))
        elif asset.trust_state in {"RESTRICTED TRUST", "UNTRUSTED"}: factors.append((f"Device trust ({asset.trust_state})", 7))
        graph_paths = [item for item in graph.get("risk_paths", []) if cve in item.get("evidence_reference", []) or component.lower() in _canonical(item).lower()]
        if graph_paths: factors.append(("Potential evidence-backed graph path", 8))
        signature = str(applicable[0].get("signature_status", "unknown")).lower()
        if signature in {"valid", "signed", "apple", "notarized"}: factors.append(("Valid software trust evidence", -4))
        score = max(0, min(100, sum(value for _, value in factors))); severity = self._severity(score)
        sources = tuple(sorted({item.source for item in relevant_intel} | {str(vuln.get("source", "NVD/vendor advisory"))}))
        refs.update(item.reference for item in relevant_intel)
        uncertainty = []
        if unknown_versions: uncertainty.append("Some matching software versions could not be evaluated; only confirmed applicable versions were scored.")
        if not relevant_intel: uncertainty.append("No valid threat-intelligence match was supplied; exploitation status is unknown.")
        exploitation = "known_exploited_in_wild" if kev else "active_exploitation_reported" if active else "public_exploit_available" if public_exploit else "unknown"
        explanation = f"{cve} applies to installed {component}. Priority uses vulnerability severity, exploit intelligence, asset importance, reachability, device trust, privilege, software trust, and graph context. This does not indicate local exploitation."
        action = f"Validate {cve} applicability and update {component} to {vuln.get('fixed_version') or 'an approved fixed version'} through an authorized vendor channel."
        reduction = min(score, 25 + (30 if kev else 0) + (8 if graph_paths else 0))
        return ExposureRecord(f"exposure-{uuid4().hex}", timestamp, asset.asset_id, "vulnerability", component, cve, self._strings(vuln.get("mitre_mapping", [])), sources, severity, cvss, exploitation, score, tuple(sorted(refs)), action, "open", tuple(f"{name}: {value:+d}" for name, value in factors), explanation, "high" if kev and cvss is not None else "medium", tuple(uncertainty), reduction, current_state={"installed_version": applicable[0].get("version"), "fixed_version": vuln.get("fixed_version")})

    def _generic(self, asset: ExposureAsset, findings: Iterable[Mapping[str, Any]], category: str, timestamp: str) -> list[ExposureRecord]:
        records = []
        for raw in findings:
            item = self._sanitize(dict(raw)); refs = tuple(sorted(set(asset.evidence_reference) | set(self._refs(item.get("evidence_reference", item.get("evidence", []))))))
            if not refs: continue
            component = str(item.get("affected_component", item.get("title", category))).strip()
            base = {"configuration": 28, "identity": 32, "supply_chain": 25}[category]
            severity_value = {"low": 2, "medium": 8, "high": 15, "critical": 23}.get(str(item.get("severity", "medium")).lower(), 8)
            score = min(100, base + severity_value + ASSET_IMPORTANCE.get(asset.importance, 3) + (7 if asset.privileged_user and category == "identity" else 0) + (7 if asset.trust_state in {"RESTRICTED TRUST", "UNTRUSTED"} else 0))
            explanation = f"{category.replace('_', ' ').title()} exposure is prioritized using observed severity, asset importance, privilege, and device trust context; no exploitation or compromise is inferred."
            records.append(ExposureRecord(f"exposure-{uuid4().hex}", timestamp, asset.asset_id, category, component, "", self._strings(item.get("mitre_mapping", item.get("mitre_attack", []))), self._strings(item.get("threat_source", [])), self._severity(score), None, "not_applicable", score, refs, str(item.get("recommendation", "Review the evidence and restore the approved security state through change control.")), str(item.get("status", "open")), (f"Category base: +{base}", f"Observed severity: +{severity_value}", f"Asset importance: +{ASSET_IMPORTANCE.get(asset.importance, 3)}"), explanation, str(item.get("confidence", "medium")), self._strings(item.get("uncertainty", [])), min(score, base), item.get("previous_state"), item.get("current_state")))
        return records

    def trend(self, current: ExposureAssessment, previous: ExposureAssessment | None) -> dict[str, Any]:
        if previous is None: return {"comparison_available": False, "current_score": current.overall_exposure_score, "new": len(current.exposures), "resolved": 0, "recurring": 0}
        key = lambda item: (item.asset_id, item.risk_category, item.affected_component, item.cve_id)
        now = {key(item): item for item in current.exposures}; before = {key(item): item for item in previous.exposures}
        resolved = len(before.keys() - now.keys()); elapsed = None
        prior_time, current_time = _parse_time(previous.timestamp), _parse_time(current.timestamp)
        if resolved and prior_time and current_time: elapsed = max(0, round((current_time - prior_time).total_seconds()))
        return {"comparison_available": True, "previous_score": previous.overall_exposure_score, "current_score": current.overall_exposure_score, "score_change": current.overall_exposure_score - previous.overall_exposure_score, "new": len(now.keys() - before.keys()), "resolved": resolved, "recurring": len(now.keys() & before.keys()), "average_remediation_seconds": elapsed, "remediation_time_qualification": "Upper-bound interval between assessments; not exact remediation execution time." if elapsed is not None else "Unavailable without a resolved exposure and two valid assessment timestamps."}

    def dashboard(self, assessment: ExposureAssessment, trend: Mapping[str, Any] | None = None, posture_graph: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {"category": "Threat Exposure Management", "overall_exposure_score": assessment.overall_exposure_score, "critical_exposures": [x.to_dict() for x in assessment.exposures if x.severity == "critical"], "known_exploited_vulnerabilities": [x.to_dict() for x in assessment.exposures if x.exploit_status == "known_exploited_in_wild"], "attack_paths": list((posture_graph or {}).get("risk_paths", [])), "risk_trends": dict(trend or {}), "recommended_actions": [assessment.exposures[i].recommendation for i in range(min(5, len(assessment.exposures)))], "actions": ["investigate", "view_evidence", "prioritize_remediation", "export_report", "create_ticket"]}

    def analyst_context(self, exposure: ExposureRecord) -> dict[str, Any]:
        return {"observed_facts": {"component": exposure.affected_component, "cve_id": exposure.cve_id, "exploit_status": exposure.exploit_status, "score_factors": list(exposure.score_factors)}, "evidence_used": list(exposure.evidence_reference), "source_categories": list(exposure.threat_source), "explanation": exposure.risk_explanation, "confidence": exposure.confidence, "uncertainty": list(exposure.uncertainty), "recommendation": exposure.recommendation, "guardrail": "Known exploitation means exploitation in the wild, not confirmed exploitation or compromise of this endpoint."}

    def incident_context(self, exposure: ExposureRecord) -> dict[str, Any]:
        eligible = exposure.severity == "critical" and exposure.confidence in {"medium", "high"}
        return {"eligible": eligible, "automatic_action": False, "authorization_required": True, "evidence_reference": list(exposure.evidence_reference), "recommended_workflow": "collect_evidence_and_request_investigation" if eligible else "track_remediation"}

    @staticmethod
    def verify_integrity(assessment: ExposureAssessment) -> bool:
        payload = assessment.to_dict(); expected = payload.pop("integrity_hash", ""); payload["integrity_hash"] = ""; return bool(expected) and _hash(payload) == expected

    @staticmethod
    def _intelligence(values: Iterable[ThreatIntelligenceMatch | Mapping[str, Any]]) -> tuple[ThreatIntelligenceMatch, ...]:
        items = []
        for value in values:
            try: item = value if isinstance(value, ThreatIntelligenceMatch) else ThreatIntelligenceMatch(**value)
            except (TypeError, ValueError): continue
            if item.valid(): items.append(item)
        return tuple(items)

    @staticmethod
    def _sanitize(value: dict[str, Any]) -> dict[str, Any]: return {k: v for k, v in value.items() if k.lower() not in SENSITIVE_KEYS and not any(x in k.lower() for x in SENSITIVE_KEYS)}
    @staticmethod
    def _refs(value: Any) -> tuple[str, ...]:
        if isinstance(value, str): value = [value]
        return tuple(str(item) for item in (value or []) if str(item).strip())
    @staticmethod
    def _strings(value: Any) -> tuple[str, ...]:
        if isinstance(value, str): value = [value]
        return tuple(str(item) for item in (value or []) if str(item).strip())
    @staticmethod
    def _cvss(value: Any) -> float | None:
        try: parsed = float(value); return parsed if 0 <= parsed <= 10 else None
        except (TypeError, ValueError): return None
    @staticmethod
    def _severity(score: int) -> str: return "critical" if score >= 80 else "high" if score >= 65 else "medium" if score >= 40 else "low"


class ThreatExposureRepository:
    def __init__(self, database: sqlite3.Connection | Path | str) -> None:
        self._owns = not isinstance(database, sqlite3.Connection); self.conn = sqlite3.connect(str(database)) if self._owns else database; self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS exposure_assessments (assessment_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, asset_id TEXT NOT NULL, exposure_score INTEGER NOT NULL, integrity_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exposure_records (exposure_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, risk_category TEXT NOT NULL, affected_component TEXT NOT NULL, cve_id TEXT NOT NULL, mitre_mapping TEXT NOT NULL, threat_source TEXT NOT NULL, severity TEXT NOT NULL, cvss_score REAL, exploit_status TEXT NOT NULL, exposure_score INTEGER NOT NULL, evidence_reference TEXT NOT NULL, recommendation TEXT NOT NULL, status TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_exposure_asset_score ON exposure_records(asset_id, exposure_score DESC);
        """); self.conn.commit()

    def close(self) -> None:
        if self._owns: self.conn.close()

    def save(self, assessment: ExposureAssessment) -> None:
        if not ThreatExposureManagementEngine.verify_integrity(assessment): raise ValueError("Refusing to store an invalid exposure assessment.")
        with self.conn:
            self.conn.execute("INSERT INTO exposure_assessments VALUES (?,?,?,?,?,?)", (assessment.assessment_id, assessment.timestamp, assessment.asset.asset_id, assessment.overall_exposure_score, assessment.integrity_hash, _canonical(assessment.to_dict())))
            for item in assessment.exposures:
                self.conn.execute("INSERT INTO exposure_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (item.exposure_id, item.asset_id, item.risk_category, item.affected_component, item.cve_id, _canonical(item.mitre_mapping), _canonical(item.threat_source), item.severity, item.cvss_score, item.exploit_status, item.exposure_score, _canonical(item.evidence_reference), item.recommendation, item.status, _canonical(item.to_dict())))

    def latest_payload(self, asset_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT payload_json FROM exposure_assessments WHERE asset_id=? ORDER BY timestamp DESC LIMIT 1", (asset_id,)).fetchone()
        if not row: return None
        payload = json.loads(row["payload_json"]); expected = payload.get("integrity_hash", ""); candidate = dict(payload); candidate["integrity_hash"] = ""
        if not expected or _hash(candidate) != expected: raise ValueError("Threat exposure assessment integrity verification failed.")
        return payload


__all__ = ["ExposureAsset", "ExposureAssessment", "ExposureRecord", "ThreatExposureManagementEngine", "ThreatExposureRepository", "ThreatIntelligenceMatch", "version_is_affected"]

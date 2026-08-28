"""Evidence-bound, local-first analyst assistance.

The assistant explains MSAA evidence. It is not an autonomous verdict or action
engine and exposes no remediation execution interface.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.privacy import redact_structure, redact_text


ALLOWED_EVIDENCE_FIELDS = {
    "finding_id", "title", "description", "severity", "confidence", "mechanism", "event_type",
    "path", "executable_path", "process_name", "parent_process", "pid", "sha256", "signature_status",
    "developer_identity", "team_id", "owner", "permissions", "risk_score", "risk_factors", "evidence",
    "mitre_attack", "nist_mapping", "cis_mapping", "cisa_mapping", "recommended_action", "timestamp",
    "network_activity", "affected_locations", "baseline_status", "source", "limitations",
}
SECRET_KEYS = ("password", "token", "secret", "private_key", "credential", "cookie", "authorization")


class AnalystAssistantError(RuntimeError):
    pass


class ExternalAnalysisProvider(Protocol):
    name: str
    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SharingPolicy:
    allow_external: bool = False
    administrator_approved: bool = False
    redact: bool = True
    provider_name: str = "local"


@dataclass
class AnalystAnalysis:
    ai_analysis_id: str
    timestamp: str
    finding_id: str
    user: str
    prompt: str
    evidence_reference: str
    observed_facts: list[str]
    analyst_interpretation: list[str]
    missing_information: list[str]
    confidence_score: int
    confidence_reason: str
    framework_mapping: dict[str, list[str]]
    recommendations: list[str]
    false_positive_considerations: list[str]
    source_categories: list[str]
    provider: str = "local_deterministic"
    human_review_required: bool = True
    external_data_shared: bool = False
    disclaimer: str = "Analyst decision support only. Verify evidence before containment, remediation, or trust decisions."

    @property
    def analysis_result(self) -> str:
        sections = ["Observed facts:", *[f"- {v}" for v in self.observed_facts], "", "Analyst interpretation:", *[f"- {v}" for v in self.analyst_interpretation], "", "Missing information:", *[f"- {v}" for v in self.missing_information]]
        return "\n".join(sections)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self); value["analysis_result"] = self.analysis_result; return value


class AnalystAuditStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path); self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS ai_analyses(
              ai_analysis_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, finding_id TEXT NOT NULL,
              user TEXT NOT NULL, prompt TEXT NOT NULL, evidence_reference TEXT NOT NULL,
              analysis_result TEXT NOT NULL, confidence_score INTEGER NOT NULL CHECK(confidence_score BETWEEN 0 AND 100),
              framework_mapping_json TEXT NOT NULL, recommendations_json TEXT NOT NULL,
              metadata_json TEXT NOT NULL
            )
        """); self.connection.commit()

    def record(self, analysis: AnalystAnalysis) -> None:
        payload = analysis.to_dict()
        self.connection.execute("INSERT INTO ai_analyses VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
            analysis.ai_analysis_id, analysis.timestamp, analysis.finding_id, redact_text(analysis.user),
            redact_text(analysis.prompt), analysis.evidence_reference, analysis.analysis_result,
            analysis.confidence_score, json.dumps(analysis.framework_mapping, sort_keys=True),
            json.dumps(analysis.recommendations), json.dumps({"provider": analysis.provider, "external_data_shared": analysis.external_data_shared, "human_review_required": True, "source_categories": analysis.source_categories}, sort_keys=True),
        )); self.connection.commit()

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM ai_analyses ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()]


class AISecurityAnalyst:
    def __init__(self, store: AnalystAuditStore, provider: ExternalAnalysisProvider | None = None) -> None:
        self.store, self.provider = store, provider

    def explain(self, finding: dict[str, Any], *, question: str, user: str, sharing: SharingPolicy | None = None) -> AnalystAnalysis:
        if not isinstance(finding, dict) or not finding:
            raise AnalystAssistantError("A structured MSAA finding is required; no analysis was generated.")
        evidence = minimize_evidence(finding)
        finding_id = str(evidence.get("finding_id") or "unassigned")
        evidence_reference = "sha256:" + hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest()
        analysis = self._local_analysis(evidence, question=question, user=user, finding_id=finding_id, evidence_reference=evidence_reference)
        policy = sharing or SharingPolicy()
        if policy.allow_external:
            if not policy.administrator_approved or self.provider is None:
                raise AnalystAssistantError("External analysis requires explicit administrator approval and a configured enterprise provider.")
            if policy.provider_name not in {self.provider.name, "configured"}:
                raise AnalystAssistantError("The approved provider does not match the configured provider.")
            outbound = redact_structure({"question": question, "evidence": evidence}) if policy.redact else {"question": question, "evidence": evidence}
            provider_result = self.provider.analyze(outbound)
            analysis.analyst_interpretation.extend(_bounded_strings(provider_result.get("interpretation"), 8))
            analysis.recommendations.extend(_bounded_strings(provider_result.get("recommendations"), 8))
            analysis.provider, analysis.external_data_shared = self.provider.name, True
            analysis.confidence_score = min(analysis.confidence_score, int(provider_result.get("confidence_score", analysis.confidence_score)))
        self.store.record(analysis)
        return analysis

    def summarize_incident(self, findings: list[dict[str, Any]], *, user: str) -> dict[str, Any]:
        analyses = [self.explain(item, question="Summarize this finding for incident review.", user=user) for item in findings[:100]]
        severities: dict[str, int] = {}
        for item in findings: severities[str(item.get("severity", "unknown")).lower()] = severities.get(str(item.get("severity", "unknown")).lower(), 0) + 1
        facts = [fact for analysis in analyses for fact in analysis.observed_facts]
        return {
            "executive_summary": f"MSAA reviewed {len(analyses)} evidence-backed finding(s). Severity counts: {severities}. Human investigation remains required.",
            "technical_summary": {"finding_ids": [item.finding_id for item in analyses], "observed_facts": facts[:50], "framework_mappings": [item.framework_mapping for item in analyses]},
            "confidence": min((item.confidence_score for item in analyses), default=0), "human_review_required": True,
        }

    def _local_analysis(self, evidence: dict[str, Any], *, question: str, user: str, finding_id: str, evidence_reference: str) -> AnalystAnalysis:
        severity = str(evidence.get("severity") or "unknown").lower(); confidence = _confidence(evidence)
        facts = _facts(evidence); mechanism = str(evidence.get("mechanism") or evidence.get("event_type") or "security finding")
        interpretation = [f"The observed {mechanism.replace('_', ' ')} evidence warrants {severity if severity != 'unknown' else 'analyst'}-priority review; this is not a malware verdict."]
        if str(evidence.get("signature_status", "")).lower() in {"unsigned", "invalid"}:
            interpretation.append("Absent or invalid signing reduces provenance assurance, but legitimate internal tools may also be unsigned.")
        if any(marker in str(evidence.get("path") or evidence.get("executable_path") or "") for marker in ("/tmp/", "/private/tmp/", "/var/tmp/")):
            interpretation.append("Execution or persistence from a temporary location is commonly abused because those locations are writable and transient.")
        missing = [label for key, label in (("sha256", "A SHA-256 value is unavailable."), ("signature_status", "Code-signing status is unavailable."), ("parent_process", "Parent-process attribution is unavailable."), ("timestamp", "Event timing is unavailable.")) if not evidence.get(key)]
        recommendations = ["Preserve the referenced evidence and verify its integrity before making changes.", "Confirm the file or process owner, business purpose, signature, hash, and first-seen history.", "Review related parent/child processes, persistence items, user activity, and network connections.", "Contain or remove artifacts only through an authorized, evidence-preserving MSAA workflow."]
        false_positives = ["Legitimate management, backup, development, synchronization, and support tools can exhibit security-sensitive behavior.", "A valid signature supports provenance but does not by itself establish benign behavior; an unsigned file is not automatically malicious."]
        frameworks = {"MITRE ATT&CK": _list(evidence.get("mitre_attack")), "NIST": _list(evidence.get("nist_mapping")), "CIS": _list(evidence.get("cis_mapping")), "CISA": _list(evidence.get("cisa_mapping"))}
        sources = ["MSAA collected evidence"] + [name for name, values in frameworks.items() if values]
        return AnalystAnalysis(f"ai-{uuid4().hex}", utc_now_iso(), finding_id, user, question, evidence_reference, facts, interpretation, missing or ["No material information gap was identified in the supplied fields; corroboration is still required."], confidence, _confidence_reason(evidence, confidence), frameworks, recommendations, false_positives, sources)


def minimize_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for key, value in finding.items():
        normalized = str(key).lower()
        if any(secret in normalized for secret in SECRET_KEYS):
            continue
        if normalized in ALLOWED_EVIDENCE_FIELDS:
            evidence[normalized] = value
    return redact_structure(evidence)


def _facts(evidence: dict[str, Any]) -> list[str]:
    labels = (("title", "Finding"), ("severity", "Recorded severity"), ("confidence", "Detector confidence"), ("path", "Observed path"), ("executable_path", "Executable"), ("process_name", "Process"), ("parent_process", "Parent process"), ("signature_status", "Signature"), ("sha256", "SHA-256"), ("baseline_status", "Baseline status"))
    facts = [f"{label}: {evidence[key]}" for key, label in labels if evidence.get(key) is not None and evidence.get(key) != "" and evidence.get(key) != [] and evidence.get(key) != {}]
    for value in _list(evidence.get("evidence"))[:8]: facts.append(f"Detector evidence: {value}")
    return facts or ["The supplied finding contains no displayable evidence fields."]


def _confidence(evidence: dict[str, Any]) -> int:
    stated = str(evidence.get("confidence", "")).lower(); score = {"high": 80, "medium": 60, "low": 35}.get(stated, 30)
    score += 5 * sum(bool(evidence.get(key)) for key in ("sha256", "signature_status", "parent_process", "timestamp"))
    return min(95, score)


def _confidence_reason(evidence: dict[str, Any], score: int) -> str:
    present = [key for key in ("sha256", "signature_status", "parent_process", "timestamp", "evidence") if evidence.get(key)]
    return f"Confidence {score}/100 reflects supplied detector confidence and corroborating fields: {', '.join(present) or 'none'}."


def _list(value: Any) -> list[str]:
    if value is None: return []
    if isinstance(value, (list, tuple, set)): return [str(item) for item in value if str(item).strip()]
    return [str(value)] if str(value).strip() else []


def _bounded_strings(value: Any, limit: int) -> list[str]:
    return [item[:1000] for item in _list(value)[:limit]]


__all__ = ["AISecurityAnalyst", "AnalystAnalysis", "AnalystAssistantError", "AnalystAuditStore", "SharingPolicy", "minimize_evidence"]

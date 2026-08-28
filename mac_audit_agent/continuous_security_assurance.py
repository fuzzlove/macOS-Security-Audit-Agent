"""Continuous, evidence-based security posture assurance for MSAA.

CSAE consumes normalized evidence from existing detectors.  It does not collect
telemetry itself and never performs remediation.  Missing evidence is unknown,
not healthy, and a framework mapping never changes a posture score.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


@dataclass(frozen=True)
class SignalDefinition:
    key: str
    domain: str
    label: str
    weight: int
    healthy: str
    severity: str
    mitre: tuple[str, ...]
    recommendation: str


@dataclass(frozen=True)
class PostureSignalResult:
    key: str
    domain: str
    label: str
    status: str
    observed_value: Any
    weight: int
    score_credit: int
    evidence_reference: tuple[str, ...]
    severity: str
    mitre_mapping: tuple[str, ...]
    explanation: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecurityPostureSnapshot:
    snapshot_id: str
    timestamp: str
    device_id: str
    hostname: str
    security_score: int
    trust_score: int
    configuration_score: int
    software_score: int
    threat_score: int
    compliance_score: int
    recovery_score: int
    evidence_coverage_percent: int
    trust_decision: str
    signals: tuple[PostureSignalResult, ...]
    score_explanation: tuple[str, ...]
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["signals"] = [item.to_dict() for item in self.signals]
        return payload


@dataclass(frozen=True)
class SecurityPostureChange:
    change_id: str
    event_id: str
    timestamp: str
    hostname: str
    category: str
    previous_state: Any
    current_state: Any
    change_type: str
    affected_component: str
    severity: str
    risk_score_change: int
    evidence_reference: tuple[str, ...]
    mitre_mapping: tuple[str, ...]
    recommended_action: str
    analyst_status: str = "new"
    description: str = ""
    correlated_change_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_SIGNALS = (
    SignalDefinition("identity_accounts_authorized", "identity", "Accounts and administrators authorized", 10, "true", "critical", ("T1098",), "Review account and administrator changes against approved change records."),
    SignalDefinition("authentication_anomalies", "identity", "Authentication anomalies", 8, "zero", "high", ("T1078",), "Review authentication timing, source, affected user, and related process evidence."),
    SignalDefinition("ssh_identity_changes", "identity", "Unauthorized SSH identity changes", 7, "zero", "critical", ("T1098",), "Preserve SSH fingerprints and validate the change with the affected user."),
    SignalDefinition("unapproved_applications", "software", "Unapproved applications", 8, "zero", "high", ("T1518",), "Validate the application against approved inventory and change records."),
    SignalDefinition("unsigned_applications", "software", "Unsigned applications requiring review", 8, "zero", "high", ("T1553.002",), "Validate provenance, signature, hash, origin, and business purpose."),
    SignalDefinition("modified_trusted_applications", "software", "Modified trusted applications", 10, "zero", "critical", ("T1195",), "Preserve both hashes and validate the update through the vendor's trusted channel."),
    SignalDefinition("known_vulnerabilities", "software", "Applicable known vulnerabilities", 7, "zero", "high", (), "Validate applicability and install an approved vendor remediation."),
    SignalDefinition("firewall_enabled", "configuration", "Firewall enabled", 7, "true", "high", ("T1562.004",), "Restore the approved firewall configuration after validating the change."),
    SignalDefinition("filevault_enabled", "configuration", "FileVault enabled", 8, "true", "critical", (), "Confirm encryption status and restore the approved encryption policy."),
    SignalDefinition("sip_enabled", "configuration", "System Integrity Protection enabled", 7, "true", "critical", ("T1562.001",), "Investigate the authorized recovery workflow and restore the approved SIP state."),
    SignalDefinition("gatekeeper_enabled", "configuration", "Gatekeeper enabled", 5, "true", "high", ("T1553.001",), "Restore the approved Gatekeeper policy and review the responsible change."),
    SignalDefinition("privacy_controls_compliant", "configuration", "Privacy controls compliant", 5, "true", "high", ("T1548",), "Review sensitive TCC grants through Apple-supported controls."),
    SignalDefinition("suspicious_persistence", "threat", "Suspicious persistence findings", 10, "zero", "critical", ("T1543.001", "T1543.004", "T1053"), "Preserve persistence configuration and executable evidence before authorized remediation."),
    SignalDefinition("ransomware_indicators", "threat", "Ransomware behavior indicators", 10, "zero", "critical", ("T1486",), "Capture evidence and initiate the authorized ransomware investigation workflow."),
    SignalDefinition("suspicious_network_activity", "threat", "Suspicious network activity", 7, "zero", "high", ("T1071", "T1105"), "Correlate the destination with process, user, and file activity evidence."),
    SignalDefinition("backup_healthy", "recovery", "Approved backup available and healthy", 8, "true", "critical", ("T1490",), "Validate protected backup availability and recovery testing status."),
    SignalDefinition("evidence_collection_ready", "recovery", "Evidence collection ready", 6, "true", "high", (), "Repair evidence collection readiness before an incident requires it."),
    SignalDefinition("response_workflow_ready", "recovery", "Incident response workflow ready", 6, "true", "high", (), "Validate authorization, containment, and recovery procedures."),
)

DOMAIN_WEIGHTS = {"identity": 20, "software": 20, "configuration": 25, "threat": 25, "recovery": 10}


class ContinuousSecurityAssuranceEngine:
    def __init__(self, definitions: Iterable[SignalDefinition] = DEFAULT_SIGNALS) -> None:
        self.definitions = tuple(definitions)
        self._validate_definitions()

    def evaluate(
        self,
        evidence: Mapping[str, Any],
        *,
        device_id: str,
        hostname: str,
        timestamp: str | None = None,
        previous: SecurityPostureSnapshot | None = None,
    ) -> tuple[SecurityPostureSnapshot, list[SecurityPostureChange]]:
        timestamp = timestamp or _utc_now()
        signals = tuple(self._evaluate_signal(item, evidence.get(item.key), evidence) for item in self.definitions)
        domain_scores = {domain: self._domain_score(signals, domain) for domain in DOMAIN_WEIGHTS}
        security_score = _clamp(sum(domain_scores[domain] * weight for domain, weight in DOMAIN_WEIGHTS.items()) / 100)
        known_weight = sum(item.weight for item in signals if item.status != "unknown")
        total_weight = sum(item.weight for item in signals)
        coverage = _clamp(100 * known_weight / total_weight) if total_weight else 0
        trust_score = _clamp((domain_scores["identity"] + domain_scores["software"] + domain_scores["configuration"]) / 3)
        compliance_score = domain_scores["configuration"]
        explanation = tuple(self._score_explanations(signals, domain_scores, security_score, coverage))
        snapshot_id = f"csae-snapshot-{uuid4().hex}"
        base = SecurityPostureSnapshot(
            snapshot_id, timestamp, device_id, hostname, security_score, trust_score,
            domain_scores["configuration"], domain_scores["software"], domain_scores["threat"],
            compliance_score, domain_scores["recovery"], coverage,
            self._trust_decision(security_score, coverage, signals), signals, explanation,
        )
        digest = hashlib.sha256(_canonical(base.to_dict()).encode("utf-8")).hexdigest()
        snapshot = SecurityPostureSnapshot(**{**base.to_dict(), "signals": signals, "score_explanation": explanation, "integrity_hash": digest})
        changes = self.compare(previous, snapshot) if previous else []
        return snapshot, self.correlate(changes, snapshot)

    def compare(self, previous: SecurityPostureSnapshot | None, current: SecurityPostureSnapshot) -> list[SecurityPostureChange]:
        if previous is None:
            return []
        before = {item.key: item for item in previous.signals}
        changes: list[SecurityPostureChange] = []
        for now in current.signals:
            old = before.get(now.key)
            if old is None or old.status == "unknown" or now.status == "unknown":
                continue
            if _canonical(old.observed_value) == _canonical(now.observed_value) and old.status == now.status:
                continue
            regression = old.status == "validated" and now.status == "concern"
            improvement = old.status == "concern" and now.status == "validated"
            change_type = "regression" if regression else "improvement" if improvement else "changed"
            impact = -self._overall_signal_impact(now) if regression else self._overall_signal_impact(now) if improvement else 0
            severity = now.severity if regression else "info" if improvement else "low"
            changes.append(SecurityPostureChange(
                f"csae-change-{uuid4().hex}", f"csae-event-{uuid4().hex}", current.timestamp, current.hostname,
                now.domain, old.observed_value, now.observed_value, change_type, now.label, severity, impact,
                now.evidence_reference, now.mitre_mapping, now.recommended_action,
                description=f"{now.label} changed from {old.status} to {now.status}.",
            ))
        return changes

    def correlate(self, changes: list[SecurityPostureChange], snapshot: SecurityPostureSnapshot) -> list[SecurityPostureChange]:
        regressions = [item for item in changes if item.change_type == "regression"]
        by_key = {signal.key: signal for signal in snapshot.signals if signal.status == "concern"}
        required = {"unsigned_applications", "suspicious_persistence", "suspicious_network_activity"}
        if required.issubset(by_key):
            sources = [item for item in regressions if any(token in item.affected_component.lower() for token in ("unsigned", "persistence", "network"))]
            if len(sources) >= 2:
                evidence = tuple(sorted({ref for key in required for ref in by_key[key].evidence_reference}))
                changes.append(SecurityPostureChange(
                    f"csae-correlation-{uuid4().hex}", f"csae-event-{uuid4().hex}", snapshot.timestamp, snapshot.hostname,
                    "cross_module_correlation", "no correlated deployment pattern", "unsigned software + persistence + network activity",
                    "correlated_regression", "Possible persistence deployment", "critical", -20, evidence,
                    ("T1543.001", "T1543.004", "T1105"),
                    "Preserve process, persistence, application, and network evidence; begin an authorized investigation.",
                    description="Multiple independently collected signals form a possible persistence deployment pattern; this is not proof of compromise.",
                    correlated_change_ids=tuple(item.change_id for item in sources),
                ))
        return changes

    def dashboard(self, snapshot: SecurityPostureSnapshot, changes: Iterable[SecurityPostureChange], history: Iterable[SecurityPostureSnapshot] = ()) -> dict[str, Any]:
        change_list = list(changes)
        points = [*history, snapshot]
        return {
            "category": "Continuous Security Assurance",
            "current_security_posture": snapshot.security_score,
            "trust_score": snapshot.trust_score,
            "trust_decision": snapshot.trust_decision,
            "evidence_coverage_percent": snapshot.evidence_coverage_percent,
            "compliance_status": "compliant" if snapshot.compliance_score >= 90 else "needs_review" if snapshot.compliance_score >= 70 else "non_compliant",
            "recent_changes": [item.to_dict() for item in change_list],
            "security_regressions": [item.to_dict() for item in change_list if item.change_type in {"regression", "correlated_regression"}],
            "risk_trend": [{"timestamp": item.timestamp, "score": item.security_score} for item in points],
            "actions": ["view_timeline", "investigate_change", "compare_snapshots", "generate_report", "start_response_workflow"],
        }

    def alert_payloads(self, changes: Iterable[SecurityPostureChange]) -> list[dict[str, Any]]:
        return [
            {
                "event_id": item.event_id, "timestamp": item.timestamp, "event_type": "continuous_security_assurance_change",
                "severity": item.severity, "source": "continuous_security_assurance", "evidence": list(item.evidence_reference),
                "recommendation": item.recommended_action, "metadata": item.to_dict(), "simulated": False,
            }
            for item in changes if item.severity in {"high", "critical"}
        ]

    def analyst_context(self, snapshot: SecurityPostureSnapshot, changes: Iterable[SecurityPostureChange]) -> dict[str, Any]:
        """Evidence-only context suitable for the AI analyst or a human analyst."""
        change_list = list(changes)
        return {
            "observed_facts": [item.to_dict() for item in change_list],
            "score_explanation": list(snapshot.score_explanation),
            "interpretation": f"Device trust decision is {snapshot.trust_decision} with {snapshot.evidence_coverage_percent}% evidence coverage.",
            "uncertainty": [item.explanation for item in snapshot.signals if item.status == "unknown"],
            "confidence": "high" if snapshot.evidence_coverage_percent >= 90 else "medium" if snapshot.evidence_coverage_percent >= 70 else "low",
            "guardrail": "This context does not establish compromise and must not trigger autonomous remediation.",
        }

    def _evaluate_signal(self, definition: SignalDefinition, raw: Any, evidence: Mapping[str, Any]) -> PostureSignalResult:
        value, refs = self._value_and_refs(raw, evidence.get("evidence_references", {}), definition.key)
        status = self._status(value, definition.healthy)
        credit = definition.weight if status == "validated" else 0
        shown = "not collected" if status == "unknown" else repr(value)
        explanation = f"{definition.label}: {status}; observed {shown}."
        return PostureSignalResult(definition.key, definition.domain, definition.label, status, value, definition.weight, credit, refs, definition.severity, definition.mitre, explanation, definition.recommendation)

    @staticmethod
    def _value_and_refs(raw: Any, references: Any, key: str) -> tuple[Any, tuple[str, ...]]:
        if isinstance(raw, Mapping) and "value" in raw:
            refs = raw.get("evidence_reference", raw.get("evidence_references", []))
            value = raw.get("value")
        else:
            value = raw
            refs = references.get(key, []) if isinstance(references, Mapping) else []
        if isinstance(refs, str): refs = [refs]
        return value, tuple(str(item) for item in refs if str(item).strip())

    @staticmethod
    def _status(value: Any, healthy: str) -> str:
        if value is None or value == "": return "unknown"
        if healthy == "zero":
            try: return "validated" if int(value) == 0 else "concern"
            except (TypeError, ValueError): return "unknown"
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "enabled", "verified", "healthy", "compliant", "approved"}: return "validated"
            if normalized in {"false", "disabled", "invalid", "unhealthy", "non_compliant", "unapproved"}: return "concern"
            return "unknown"
        return "validated" if value is True else "concern" if value is False else "unknown"

    def _domain_score(self, signals: tuple[PostureSignalResult, ...], domain: str) -> int:
        selected = [item for item in signals if item.domain == domain]
        total = sum(item.weight for item in selected)
        return _clamp(100 * sum(item.score_credit for item in selected) / total) if total else 0

    def _overall_signal_impact(self, signal: PostureSignalResult) -> int:
        domain_total = sum(item.weight for item in self.definitions if item.domain == signal.domain)
        return max(1, round(DOMAIN_WEIGHTS[signal.domain] * signal.weight / domain_total))

    @staticmethod
    def _trust_decision(score: int, coverage: int, signals: tuple[PostureSignalResult, ...]) -> str:
        if coverage < 60: return "INSUFFICIENT EVIDENCE"
        if any(item.status == "concern" and item.severity == "critical" for item in signals): return "RESTRICTED TRUST"
        if score >= 90: return "VERIFIED TRUST"
        if score >= 70: return "CONDITIONAL TRUST"
        return "RESTRICTED TRUST"

    @staticmethod
    def _score_explanations(signals: tuple[PostureSignalResult, ...], domains: dict[str, int], score: int, coverage: int) -> list[str]:
        lines = [f"Overall score {score}/100 from weighted domain scores: " + ", ".join(f"{key}={value}" for key, value in domains.items()) + ".", f"Evidence coverage is {coverage}%; unknown signals receive no trust credit."]
        lines.extend(f"No credit: {item.explanation}" for item in signals if item.status in {"concern", "unknown"})
        return lines

    def _validate_definitions(self) -> None:
        keys: set[str] = set()
        for item in self.definitions:
            if item.key in keys or item.domain not in DOMAIN_WEIGHTS or item.healthy not in {"true", "zero"} or item.weight <= 0:
                raise ValueError(f"Invalid CSAE signal definition: {item.key}")
            keys.add(item.key)


class SecurityAssuranceRepository:
    """Durable CSAE history using an existing SQLite connection or database path."""
    def __init__(self, database: sqlite3.Connection | Path | str) -> None:
        self._owns_connection = not isinstance(database, sqlite3.Connection)
        self.conn = sqlite3.connect(str(database)) if self._owns_connection else database
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        if self._owns_connection: self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_posture_history (
          snapshot_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, device_id TEXT NOT NULL, hostname TEXT NOT NULL,
          security_score INTEGER NOT NULL, trust_score INTEGER NOT NULL, configuration_score INTEGER NOT NULL,
          software_score INTEGER NOT NULL, threat_score INTEGER NOT NULL, compliance_score INTEGER NOT NULL,
          recovery_score INTEGER NOT NULL, evidence_coverage_percent INTEGER NOT NULL, integrity_hash TEXT NOT NULL,
          payload_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_security_posture_device_time ON security_posture_history(device_id, timestamp DESC);
        CREATE TABLE IF NOT EXISTS security_changes (
          change_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL, hostname TEXT NOT NULL,
          component TEXT NOT NULL, previous_value TEXT NOT NULL, new_value TEXT NOT NULL, risk_impact INTEGER NOT NULL,
          severity TEXT NOT NULL, evidence_json TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_security_changes_time ON security_changes(timestamp DESC);
        """)
        self.conn.commit()

    def save(self, snapshot: SecurityPostureSnapshot, changes: Iterable[SecurityPostureChange]) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO security_posture_history VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                snapshot.snapshot_id, snapshot.timestamp, snapshot.device_id, snapshot.hostname, snapshot.security_score,
                snapshot.trust_score, snapshot.configuration_score, snapshot.software_score, snapshot.threat_score,
                snapshot.compliance_score, snapshot.recovery_score, snapshot.evidence_coverage_percent,
                snapshot.integrity_hash, _canonical(snapshot.to_dict()),
            ))
            for item in changes:
                self.conn.execute("INSERT INTO security_changes VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
                    item.change_id, item.event_id, item.timestamp, item.hostname, item.affected_component,
                    _canonical(item.previous_state), _canonical(item.current_state), item.risk_score_change,
                    item.severity, _canonical(item.evidence_reference), _canonical(item.to_dict()),
                ))

    def latest(self, device_id: str) -> SecurityPostureSnapshot | None:
        row = self.conn.execute("SELECT payload_json FROM security_posture_history WHERE device_id=? ORDER BY timestamp DESC LIMIT 1", (device_id,)).fetchone()
        if not row: return None
        snapshot = self._snapshot(json.loads(row["payload_json"]))
        if not self.verify_snapshot(snapshot):
            raise ValueError(f"CSAE snapshot integrity verification failed: {snapshot.snapshot_id}")
        return snapshot

    def history(self, device_id: str, limit: int = 100) -> list[SecurityPostureSnapshot]:
        rows = self.conn.execute("SELECT payload_json FROM security_posture_history WHERE device_id=? ORDER BY timestamp DESC LIMIT ?", (device_id, max(1, min(limit, 1000)))).fetchall()
        snapshots = [self._snapshot(json.loads(row["payload_json"])) for row in rows]
        invalid = [item.snapshot_id for item in snapshots if not self.verify_snapshot(item)]
        if invalid:
            raise ValueError(f"CSAE snapshot integrity verification failed: {', '.join(invalid)}")
        return snapshots

    def changes(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT payload_json FROM security_changes ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    @staticmethod
    def verify_snapshot(snapshot: SecurityPostureSnapshot) -> bool:
        payload = snapshot.to_dict()
        expected = str(payload.pop("integrity_hash", ""))
        payload["integrity_hash"] = ""
        return bool(expected) and hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest() == expected

    @staticmethod
    def _snapshot(payload: dict[str, Any]) -> SecurityPostureSnapshot:
        payload["signals"] = tuple(PostureSignalResult(**item) for item in payload.get("signals", []))
        payload["score_explanation"] = tuple(payload.get("score_explanation", []))
        return SecurityPostureSnapshot(**payload)


__all__ = ["ContinuousSecurityAssuranceEngine", "DEFAULT_SIGNALS", "SecurityAssuranceRepository", "SecurityPostureChange", "SecurityPostureSnapshot"]

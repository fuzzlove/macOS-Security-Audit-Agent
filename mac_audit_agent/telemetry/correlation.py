from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.telemetry.models import BehavioralAnomaly, BehavioralIncident, utc_now_iso
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.storage import TelemetryRepository


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class BehavioralCorrelationEngine:
    def __init__(self, database, repository: TelemetryRepository, policy: BehavioralTelemetryPolicy) -> None:
        self.db = database
        self.repository = repository
        self.policy = policy

    def correlate(self, anomalies: list[BehavioralAnomaly]) -> BehavioralIncident | None:
        if not anomalies:
            return None
        anomalies.sort(key=lambda item: item.timestamp)
        anchor = anomalies[-1]
        primary_entity = next((value for key in ("process", "path", "destination", "domain") for value in [anchor.related_entities.get(key, "")] if value), "")
        since = (_parse(anchor.timestamp) - timedelta(seconds=self.policy.correlation_window_seconds)).isoformat()
        existing = self.repository.find_correlatable_incident(
            host_ref=anchor.host_ref, user_ref=anchor.user_ref, primary_entity=primary_entity, since=since,
        )
        if existing:
            incident = BehavioralIncident(
                incident_id=str(existing["incident_id"]), first_seen=str(existing["first_seen"]), last_seen=anchor.timestamp,
                host_ref=anchor.host_ref,user_ref=anchor.user_ref,primary_entity=str(existing["primary_entity"] or primary_entity),
                anomaly_ids=list(dict.fromkeys([*existing["anomaly_ids"], *(item.anomaly_id for item in anomalies)])),
                reason_codes=list(dict.fromkeys([*existing["reason_codes"], *(code for item in anomalies for code in item.reason_codes)])),
                anomaly_score=max(int(existing["anomaly_score"]), max(item.anomaly_score for item in anomalies)),
                security_severity=_highest([str(existing["security_severity"]), *(item.security_severity for item in anomalies)]),
                detection_confidence=max(float(existing["detection_confidence"]), max(item.detection_confidence for item in anomalies)),
                evidence_refs=list(dict.fromkeys([*existing["evidence_refs"], *(ref for item in anomalies for ref in item.evidence_refs)])),
                status=str(existing["status"]),alert_event_id=str(existing["alert_event_id"]),
                flight_recorder_snapshot_id=str(existing["flight_recorder_snapshot_id"]),
                occurrence_count=int(existing["occurrence_count"]) + len(anomalies),
            )
        else:
            incident = BehavioralIncident(
                incident_id=f"BINC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:10].upper()}",
                first_seen=anomalies[0].timestamp,last_seen=anchor.timestamp,host_ref=anchor.host_ref,user_ref=anchor.user_ref,
                primary_entity=primary_entity,anomaly_ids=[item.anomaly_id for item in anomalies],
                reason_codes=list(dict.fromkeys(code for item in anomalies for code in item.reason_codes)),
                anomaly_score=max(item.anomaly_score for item in anomalies),
                security_severity=_highest([item.security_severity for item in anomalies]),
                detection_confidence=max(item.detection_confidence for item in anomalies),
                evidence_refs=list(dict.fromkeys(ref for item in anomalies for ref in item.evidence_refs)),
                occurrence_count=len(anomalies),
            )
        diversity_bonus = min(15, max(0, len(set(item.dimension for item in anomalies)) - 1) * 5)
        incident.anomaly_score = min(100, incident.anomaly_score + diversity_bonus)
        if incident.anomaly_score >= self.policy.investigation_threshold:
            if not incident.flight_recorder_snapshot_id:
                incident.flight_recorder_snapshot_id = f"flight-{uuid4().hex}"
            # Refresh the same bounded snapshot while related post-event
            # observations arrive; INSERT OR REPLACE preserves one timeline.
            refs = self.repository.preserve_context(
                snapshot_id=incident.flight_recorder_snapshot_id,incident_id=incident.incident_id,anchor_time=incident.last_seen,
                pre_seconds=self.policy.pre_event_window_seconds,post_seconds=self.policy.post_event_window_seconds,
            )
            incident.evidence_refs = list(dict.fromkeys([*incident.evidence_refs, *refs]))
        alert_warranted = self._alert_warranted(incident) and not incident.alert_event_id
        self.repository.save_incident(incident)
        self.repository.commit()
        if alert_warranted:
            # Release the analytics writer transaction before publishing into
            # the canonical alert connection, then persist the returned ID.
            incident.alert_event_id = self._publish_alert(incident)
            self.repository.save_incident(incident)
            self.repository.commit()
        return incident

    def _alert_warranted(self, incident: BehavioralIncident) -> bool:
        return (
            incident.anomaly_score >= self.policy.alert_threshold
            and SEVERITY_RANK.get(incident.security_severity, 0) >= SEVERITY_RANK["high"]
            and len(set(incident.reason_codes)) >= 3
        ) or "DETERMINISTIC_INTELLIGENCE_MATCH" in incident.reason_codes

    def _publish_alert(self, incident: BehavioralIncident) -> str:
        event_id = f"behavioral-alert-{incident.incident_id.lower()}"
        evidence = (
            f"Behavior deviated materially from the local baseline. Score {incident.anomaly_score}/100; "
            f"{len(incident.reason_codes)} correlated reason codes; {incident.occurrence_count} related anomaly observations."
        )
        event = BackgroundMonitorEvent(
            event_id=event_id,timestamp=incident.last_seen,event_type="behavioral_anomaly",severity=incident.security_severity,
            source="behavioral_telemetry_correlation",process_name="",evidence=evidence,
            confidence="high" if incident.detection_confidence >= 0.80 else "medium" if incident.detection_confidence >= 0.50 else "low",
            recommendation="Open Behavioral Telemetry and Investigation Priority; validate the process tree, destinations, persistence, privilege, and canonical evidence references.",
            metadata_json=json.dumps({
                "incident_id":incident.incident_id,"anomaly_score":incident.anomaly_score,"reason_codes":incident.reason_codes,
                "evidence_refs":incident.evidence_refs[:512],"behavior_model_version":"robust-statistics-1.0",
                "feature_schema_version":"1.0","active_behavior_policy":self.policy.profile,
            },sort_keys=True),correlation_id=incident.incident_id,source_trace=incident.incident_id,
        )
        self.db.record_monitor_event(event, dedupe_window_seconds=0)
        return event_id


def _highest(values: list[str]) -> str:
    return max(values or ["info"], key=lambda value: SEVERITY_RANK.get(str(value).lower(), 0)).lower()


def _parse(value: str) -> datetime:
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


__all__ = ["BehavioralCorrelationEngine"]

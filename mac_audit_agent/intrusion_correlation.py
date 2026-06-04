from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from mac_audit_agent.models import BackgroundMonitorEvent, Finding, ScanResult, utc_now_iso
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer, WorkflowContextWindow


PHYSICAL_SESSION_EVENTS = {
    "lid_opened",
    "lid_closed",
    "possible_lid_opened",
    "possible_lid_closed",
    "display_wake",
    "display_sleep",
    "screen_unlocked",
    "screen_locked",
    "user_logged_in",
    "user_logged_out",
    "idle_resume_detected",
    "mouse_or_keyboard_activity_after_idle",
    "input_activity_resumed_after_idle",
}
DEVICE_EVENTS = {
    "usb_device_connected",
    "usb_device_removed",
    "new_usb_device_detected",
    "current_usb_device_inventory_changed",
    "bluetooth_device_connected",
    "bluetooth_device_disconnected",
    "bluetooth_activity_started",
    "bluetooth_activity_stopped",
    "unknown_hid_device_detected",
}
NETWORK_EVENTS = {
    "new_network_connection_detected",
    "new_ip_assigned",
    "network_ip_assigned",
    "vpn_connected",
    "vpn_disconnected",
    "new_gateway_detected",
    "new_dns_server_detected",
}
PERSISTENCE_EVENTS = {
    "new_admin_user_detected",
    "admin_user_removed",
    "launchagent_added",
    "launchdaemon_added",
    "login_item_added",
    "persistence_item_created_high_risk",
    "remote_login_enabled",
    "screen_sharing_enabled",
}
EXECUTION_EVENTS = {
    "unexpected_execution_activity",
    "execution_evidence_detected",
    "capture_capable_process_observed",
    "suspicious_process_observed",
}


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _event_dict(event: BackgroundMonitorEvent | Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    if hasattr(event, "to_dict"):
        return event.to_dict()
    return dict(getattr(event, "__dict__", {}))


def _redact(value: str, *, usernames: bool = True, ips: bool = True) -> str:
    result = str(value)
    if ips:
        result = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP REDACTED]", result)
    if usernames:
        result = re.sub(r"(?i)\b(user(name)?|console user|current user)\s*[:=]\s*([A-Za-z0-9._-]+)", r"\1: [USER REDACTED]", result)
        result = re.sub(r"/Users/([^/\s]+)/", "/Users/[USER REDACTED]/", result)
    return result


@dataclass
class IntrusionPattern:
    pattern_id: str
    title: str
    severity: str
    confidence: str
    related_events: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    why_it_matters: str = ""
    recommended_next_steps: list[str] = field(default_factory=list)
    evidence_to_preserve: list[str] = field(default_factory=list)
    false_positive_notes: list[str] = field(default_factory=list)
    source_trace: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UserPresenceConfidence:
    state: str
    reason: str
    confidence: str
    idle_minutes: int = 0
    trusted_input_detected: bool = False
    recent_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoringCoverageScore:
    score: int
    summary: str
    missing: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IntrusionCorrelationReport:
    generated_at: str
    scan_id: str
    summary: str
    patterns: list[IntrusionPattern] = field(default_factory=list)
    top_patterns: list[IntrusionPattern] = field(default_factory=list)
    user_presence: UserPresenceConfidence | None = None
    coverage: MonitoringCoverageScore | None = None
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    ai_summary: dict[str, Any] = field(default_factory=dict)
    ai_summary_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "scan_id": self.scan_id,
            "summary": self.summary,
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "top_patterns": [pattern.to_dict() for pattern in self.top_patterns],
            "user_presence": self.user_presence.to_dict() if self.user_presence else {},
            "coverage": self.coverage.to_dict() if self.coverage else {},
            "recent_events": list(self.recent_events),
            "ai_summary": dict(self.ai_summary),
            "ai_summary_path": self.ai_summary_path,
            "counts": {
                "patterns": len(self.patterns),
                "top_patterns": len(self.top_patterns),
                "recent_events": len(self.recent_events),
            },
        }


class IntrusionCorrelationEngine:
    def __init__(self, db: AuditDatabase, workflow_layer: InvestigatorWorkflowLayer | None = None) -> None:
        self.db = db
        self.workflow_layer = workflow_layer or InvestigatorWorkflowLayer(db)

    def build_report(
        self,
        *,
        scan_result: ScanResult | None = None,
        recent_limit: int = 250,
        window_minutes: int = 15,
    ) -> IntrusionCorrelationReport:
        now = utc_now_iso()
        recent_events = [event.to_dict() for event in self.db.recent_background_monitor_events(limit=recent_limit)]
        if scan_result is not None:
            findings = [finding.to_dict() if hasattr(finding, "to_dict") else dict(getattr(finding, "__dict__", {})) for finding in scan_result.findings]
            scan_id = scan_result.scan_id
            anchor_timestamp = scan_result.timestamp
        else:
            findings = []
            latest_scan = self.db.latest_scan_result()
            scan_id = latest_scan.scan_id if latest_scan else ""
            anchor_timestamp = recent_events[0]["timestamp"] if recent_events else now
        patterns = self._build_patterns(recent_events=recent_events, findings=findings)
        user_presence = self._user_presence_confidence(recent_events)
        coverage = self._monitoring_coverage()
        summary = self._summary_text(patterns, user_presence, coverage)
        top_patterns = patterns[:3]
        ai_summary = self.build_ai_summary(
            patterns=patterns,
            recent_events=recent_events,
            findings=findings,
            redact_usernames=self.db.get_background_monitor_state("redact_usernames", "1") == "1",
            redact_ips=self.db.get_background_monitor_state("redact_ips", "1") == "1",
        )
        ai_path = self.write_ai_summary(ai_summary)
        return IntrusionCorrelationReport(
            generated_at=now,
            scan_id=scan_id,
            summary=summary,
            patterns=patterns,
            top_patterns=top_patterns,
            user_presence=user_presence,
            coverage=coverage,
            recent_events=recent_events,
            ai_summary=ai_summary,
            ai_summary_path=str(ai_path),
        )

    def build_context_window_for_event(self, event: dict[str, Any] | BackgroundMonitorEvent, *, window_minutes: int = 15) -> WorkflowContextWindow:
        payload = _event_dict(event)
        anchor_timestamp = str(payload.get("timestamp", utc_now_iso()))
        return self.workflow_layer.build_context_window(
            anchor_timestamp,
            focus_label=str(payload.get("event_type", "monitor event")),
            focus_kind="monitor_event",
            focus_category=str(payload.get("trigger_source", payload.get("source", ""))),
            focus_id=str(payload.get("event_id", "")),
            focus_event_id=str(payload.get("event_id", "")),
            window_minutes=window_minutes,
        )

    def _build_patterns(self, *, recent_events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[IntrusionPattern]:
        events = sorted(recent_events, key=lambda item: _parse_timestamp(item.get("timestamp", utc_now_iso())))
        patterns: list[IntrusionPattern] = []
        patterns.extend(self._pattern_physical_usb(events))
        patterns.extend(self._pattern_process_network_persistence(events, findings))
        patterns.extend(self._pattern_admin_login(events, findings))
        patterns.extend(self._pattern_launchd_trust(events, findings))
        patterns.extend(self._pattern_vpn_network_process(events, findings))
        patterns.extend(self._pattern_storm_tamper(events))
        return self._dedupe_patterns(patterns)

    def _pattern_physical_usb(self, events: list[dict[str, Any]]) -> list[IntrusionPattern]:
        physical = self._recent(events, PHYSICAL_SESSION_EVENTS)
        usb = self._recent(events, {"usb_device_connected", "new_usb_device_detected", "current_usb_device_inventory_changed"})
        if not physical or not usb:
            return []
        related = self._nearest_group(events, physical + usb, window_minutes=15)
        if len({item.get("event_type", "") for item in related}) < 2:
            return []
        return [
            self._build_pattern(
                "physical_access_usb_activity",
                "Physical access followed by device activity",
                "high" if any(item.get("severity") == "critical" for item in related) else "medium",
                "high" if len(related) >= 3 else "medium",
                related,
                why="A lid, display, or session change followed by USB activity can be consistent with hands-on use at the device.",
                next_steps=[
                    "Review the timeline around the session change.",
                    "Confirm whether the USB device was expected.",
                ],
                preserve=[
                    "Background monitor events",
                    "USB inventory snapshot",
                    "Session and display timeline",
                ],
                false_positive=[
                    "Legitimate user login or docking station use can produce the same sequence.",
                ],
            )
        ]

    def _pattern_process_network_persistence(self, events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[IntrusionPattern]:
        network = self._recent(events, {"new_network_connection_detected", "network_ip_assigned", "new_ip_assigned", "vpn_connected"})
        persistence = self._recent(events, PERSISTENCE_EVENTS | {"launchdaemon_added", "launchagent_added", "login_item_added"})
        process = [item for item in events if "process" in str(item.get("event_type", "")) or "execution" in str(item.get("event_type", ""))]
        if not network or not persistence or not process:
            return []
        related = self._nearest_group(events, network + persistence + process, window_minutes=20)
        if len(related) < 3:
            return []
        return [
            self._build_pattern(
                "process_network_persistence",
                "New process, network activity, and persistence change",
                "critical" if any(item.get("severity") == "critical" for item in persistence) else "high",
                "medium",
                related,
                why="A process change followed by network activity and persistence creation can indicate an activity chain worth investigation.",
                next_steps=[
                    "Open the surrounding timeline.",
                    "Compare the process path and parent process.",
                    "Review new persistence items first.",
                ],
                preserve=["Process inventory", "Network state", "Persistence inventory", "Relevant logs"],
                false_positive=["Updater, installer, or management tooling may follow this sequence."],
            )
        ]

    def _pattern_admin_login(self, events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[IntrusionPattern]:
        admin = self._recent(events, {"new_admin_user_detected", "admin_user_removed"})
        login = self._recent(events, {"user_logged_in", "screen_unlocked"})
        sudoers = [item for item in findings if "sudo" in str(item.get("title", "")).lower() or "sudo" in str(item.get("evidence", "")).lower()]
        if not admin or not login:
            return []
        related = self._nearest_group(events, admin + login, window_minutes=30)
        if len(related) < 2:
            return []
        severity = "critical" if sudoers else "high"
        return [
            self._build_pattern(
                "admin_login_change",
                "Admin change with login activity",
                severity,
                "high",
                related,
                why="Administrative account changes paired with a login event deserve review because they can alter who controls the system.",
                next_steps=["Verify whether the account change was authorized.", "Review recent admin activity and notes."],
                preserve=["Admin/user inventory", "Authentication logs", "Timeline around the login event"],
                false_positive=["Managed enrollment or IT maintenance can create legitimate admin changes."],
            )
        ]

    def _pattern_launchd_trust(self, events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[IntrusionPattern]:
        launchd = self._recent(events, {"launchdaemon_added", "launchagent_added"})
        low_trust = [item for item in findings if self._trust_score(item) and self._trust_score(item) < 70]
        if not launchd or not low_trust:
            return []
        related = self._nearest_group(events, launchd + low_trust, window_minutes=30)
        if len(related) < 2:
            return []
        return [
            self._build_pattern(
                "launchd_trust_anomaly",
                "Launchd change with low trust score",
                "high",
                "medium",
                related,
                why="A new LaunchDaemon or LaunchAgent combined with a low-trust binary is consistent with a persistence change worth reviewing.",
                next_steps=["Inspect the plist target and owning files.", "Review the binary trust details before taking action."],
                preserve=["Plist file", "Runtime hash manifest", "Process inventory", "Relevant logs"],
                false_positive=["Legitimate software updates may replace launch items and lower trust until re-baselined."],
            )
        ]

    def _pattern_vpn_network_process(self, events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[IntrusionPattern]:
        vpn = self._recent(events, {"vpn_disconnected"})
        network = self._recent(events, {"new_network_connection_detected", "new_ip_assigned", "network_ip_assigned"})
        suspicious = [item for item in events if str(item.get("event_type", "")).startswith("suspicious") or "unknown" in str(item.get("evidence", "")).lower()]
        if not vpn or not network or not suspicious:
            return []
        related = self._nearest_group(events, vpn + network + suspicious, window_minutes=20)
        if len(related) < 3:
            return []
        return [
            self._build_pattern(
                "vpn_network_process",
                "VPN disconnect followed by network and process change",
                "high",
                "medium",
                related,
                why="A VPN state change followed by new network activity and an unknown process is a useful investigation signal.",
                next_steps=["Check whether the VPN change was expected.", "Review the unknown process path and parentage."],
                preserve=["VPN status", "Network inventory", "Process inventory", "Relevant logs"],
                false_positive=["Endpoint switching networks during a normal user session can look similar."],
            )
        ]

    def _pattern_storm_tamper(self, events: list[dict[str, Any]]) -> list[IntrusionPattern]:
        storm = self._recent(events, {"alert_storm_detected"})
        tamper = self._recent(events, {"protected_monitor_tamper_detected"})
        detector_failure = self.db.get_background_monitor_state("last_error", "")
        if not storm and not tamper and not detector_failure:
            return []
        related = self._nearest_group(events, storm + tamper, window_minutes=60) if (storm or tamper) else []
        return [
            self._build_pattern(
                "storm_tamper_blindness",
                "Alert storm with tamper or detector failure",
                "critical" if tamper else "high",
                "high" if tamper else "medium",
                related,
                why="Alert storms and monitor tamper or detector failure can reduce visibility and deserve immediate review.",
                next_steps=["Preserve logs and verify detector health.", "Review the monitor runtime and recent admin activity."],
                preserve=["Monitor logs", "Background monitor state", "Runtime manifest", "Relevant snapshots"],
                false_positive=["Heavy installer or update activity can cause transient noise."],
            )
        ]

    def _build_pattern(
        self,
        pattern_id: str,
        title: str,
        severity: str,
        confidence: str,
        related_events: list[dict[str, Any]],
        *,
        why: str,
        next_steps: list[str],
        preserve: list[str],
        false_positive: list[str],
    ) -> IntrusionPattern:
        ordered = sorted(related_events, key=lambda item: _parse_timestamp(item.get("timestamp", utc_now_iso())))
        timeline = [
            {
                "timestamp": str(item.get("timestamp", "")),
                "event_type": str(item.get("event_type", "")),
                "severity": str(item.get("severity", "")),
                "evidence": str(item.get("evidence", item.get("summary", ""))),
                "correlation_id": str(item.get("correlation_id", "")),
            }
            for item in ordered
        ]
        return IntrusionPattern(
            pattern_id=pattern_id,
            title=title,
            severity=severity,
            confidence=confidence,
            related_events=ordered,
            timeline=timeline,
            why_it_matters=why,
            recommended_next_steps=list(next_steps),
            evidence_to_preserve=list(preserve),
            false_positive_notes=list(false_positive),
            source_trace="intrusion_correlation",
        )

    def _dedupe_patterns(self, patterns: list[IntrusionPattern]) -> list[IntrusionPattern]:
        seen: set[str] = set()
        deduped: list[IntrusionPattern] = []
        for pattern in patterns:
            if pattern.pattern_id in seen:
                continue
            seen.add(pattern.pattern_id)
            deduped.append(pattern)
        deduped.sort(key=lambda item: (-self._severity_rank(item.severity), -self._confidence_rank(item.confidence), item.title.lower()))
        return deduped

    def _severity_rank(self, severity: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)

    def _confidence_rank(self, confidence: str) -> int:
        return {"high": 2, "medium": 1, "low": 0}.get(confidence, 0)

    def _recent(self, events: list[dict[str, Any]], types: set[str], *, hours: int = 168) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [item for item in events if item.get("event_type") in types and _parse_timestamp(item.get("timestamp", utc_now_iso())) >= cutoff]

    def _nearest_group(self, events: list[dict[str, Any]], candidates: list[dict[str, Any]], *, window_minutes: int) -> list[dict[str, Any]]:
        if not candidates:
            return []
        ordered = sorted(candidates, key=lambda item: _parse_timestamp(item.get("timestamp", utc_now_iso())))
        start = _parse_timestamp(ordered[0].get("timestamp", utc_now_iso())) - timedelta(minutes=window_minutes)
        end = _parse_timestamp(ordered[-1].get("timestamp", utc_now_iso())) + timedelta(minutes=window_minutes)
        return [item for item in events if start <= _parse_timestamp(item.get("timestamp", utc_now_iso())) <= end]

    def _trust_score(self, finding: dict[str, Any]) -> int | None:
        for key in ("trust_score", "score", "binary_trust_score"):
            value = finding.get(key)
            if value is None:
                continue
            try:
                return int(float(value))
            except (TypeError, ValueError):
                continue
        evidence = str(finding.get("evidence", "")).lower()
        if "low trust" in evidence:
            return 50
        return None

    def _summary_text(self, patterns: list[IntrusionPattern], presence: UserPresenceConfidence, coverage: MonitoringCoverageScore) -> str:
        if not patterns:
            return f"No possible intrusion patterns were identified. Monitoring coverage is {coverage.score}%, user presence is {presence.state}."
        strongest = patterns[0]
        return (
            f"Identified {len(patterns)} possible intrusion pattern(s). "
            f"Top pattern: {strongest.title}. "
            f"Monitoring coverage is {coverage.score}% and user presence is {presence.state}."
        )

    def _user_presence_confidence(self, events: list[dict[str, Any]]) -> UserPresenceConfidence:
        recent = sorted(events, key=lambda item: _parse_timestamp(item.get("timestamp", utc_now_iso())), reverse=True)[:50]
        trusted_input = any(item.get("event_type") in {"usb_device_connected", "bluetooth_device_connected", "screen_unlocked", "user_logged_in"} for item in recent)
        idle_started = next((item for item in recent if item.get("event_type") == "input_activity_idle_started"), None)
        resumed = next((item for item in recent if item.get("event_type") in {"input_activity_resumed_after_idle", "idle_resume_detected", "mouse_or_keyboard_activity_after_idle"}), None)
        idle_minutes = 0
        if idle_started and resumed:
            try:
                idle_minutes = max(0, int((_parse_timestamp(resumed["timestamp"]) - _parse_timestamp(idle_started["timestamp"])).total_seconds() / 60))
            except Exception:
                idle_minutes = 0
        if resumed and idle_minutes >= 60 and not trusted_input:
            state = "suspicious_activity_window"
            confidence = "high"
            reason = f"Activity occurred after {idle_minutes} minutes idle with no trusted input device present."
        elif trusted_input or any(item.get("event_type") in {"screen_unlocked", "user_logged_in", "display_wake"} for item in recent):
            state = "present_likely"
            confidence = "medium"
            reason = "Recent screen or input activity suggests a person is likely present."
        else:
            state = "unknown"
            confidence = "low"
            reason = "Recent signals are insufficient to determine user presence confidently."
        return UserPresenceConfidence(
            state=state,
            reason=reason,
            confidence=confidence,
            idle_minutes=idle_minutes,
            trusted_input_detected=trusted_input,
            recent_events=recent[:10],
        )

    def _monitoring_coverage(self) -> MonitoringCoverageScore:
        score = 100
        missing: list[str] = []
        checks: list[dict[str, Any]] = []

        def mark(name: str, value: Any, penalty: int = 0, fail_text: str | None = None) -> None:
            nonlocal score
            checks.append({"name": name, "value": value, "penalty": penalty})
            if penalty:
                score = max(0, score - penalty)
                if fail_text:
                    missing.append(fail_text)

        state = {row["key"]: row["value"] for row in self.db.conn.execute("SELECT key, value FROM background_monitor_state")}
        heartbeat = state.get("last_heartbeat", "")
        last_event = state.get("last_event_timestamp", "")
        detector_last_run = state.get("detector_last_run_timestamp", "")
        monitor_mode = state.get("monitor_mode", state.get("monitor_install_mode", "user"))
        mark("monitor_mode", monitor_mode)
        if state.get("running", "0") != "1" or state.get("loaded", "0") != "1":
            mark("monitor_running", False, 20, "monitor stopped or not loaded")
        else:
            mark("monitor_running", True)
        if state.get("notification_status", "").startswith("failed"):
            mark("notifier", state.get("notification_status"), 10, "notifier broken")
        else:
            mark("notifier", state.get("notification_status", "unknown"))
        if state.get("monitor_protection_status") == "tamper detected":
            mark("tamper", "tamper detected", 20, "LaunchDaemon or runtime tamper detected")
        else:
            mark("tamper", state.get("monitor_protection_status", "verified"))
        if not heartbeat:
            mark("heartbeat", "missing", 15, "heartbeat missing")
        else:
            try:
                if datetime.now(timezone.utc) - _parse_timestamp(heartbeat) > timedelta(minutes=30):
                    mark("heartbeat", heartbeat, 20, "heartbeat stale")
                else:
                    mark("heartbeat", heartbeat)
            except Exception:
                mark("heartbeat", heartbeat, 10, "heartbeat unreadable")
        if not detector_last_run:
            mark("detector_last_run", "missing", 10, "detector has not run")
        else:
            try:
                if datetime.now(timezone.utc) - _parse_timestamp(detector_last_run) > timedelta(minutes=30):
                    mark("detector_last_run", detector_last_run, 10, "detector stale")
                else:
                    mark("detector_last_run", detector_last_run)
            except Exception:
                mark("detector_last_run", detector_last_run, 5, "detector timestamp invalid")
        if last_event:
            try:
                if datetime.now(timezone.utc) - _parse_timestamp(last_event) > timedelta(hours=2):
                    mark("last_event", last_event, 10, "events not updating")
                else:
                    mark("last_event", last_event)
            except Exception:
                mark("last_event", last_event, 5, "last event timestamp invalid")
        if monitor_mode in {"system", "protected"} and state.get("plist_path", "").startswith(str(Path.home())):
            mark("plist_location", state.get("plist_path", ""), 10, "monitor plist is not system-owned")
        coverage = max(0, min(100, score))
        summary = f"Monitoring Coverage: {coverage}%"
        if missing:
            summary += f". Missing: {', '.join(missing[:4])}"
        return MonitoringCoverageScore(score=coverage, summary=summary, missing=missing, checks=checks)

    def build_ai_summary(
        self,
        *,
        patterns: list[IntrusionPattern],
        recent_events: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        redact_usernames: bool = True,
        redact_ips: bool = True,
    ) -> dict[str, Any]:
        redacted_patterns = []
        for pattern in patterns:
            item = pattern.to_dict()
            item["why_it_matters"] = _redact(item["why_it_matters"], usernames=redact_usernames, ips=redact_ips)
            item["recommended_next_steps"] = [_redact(step, usernames=redact_usernames, ips=redact_ips) for step in item["recommended_next_steps"]]
            item["evidence_to_preserve"] = [_redact(step, usernames=redact_usernames, ips=redact_ips) for step in item["evidence_to_preserve"]]
            redacted_patterns.append(item)
        redacted_events = []
        for item in recent_events[:100]:
            redacted_events.append(
                {
                    "timestamp": item.get("timestamp", ""),
                    "event_type": item.get("event_type", ""),
                    "severity": item.get("severity", ""),
                    "summary": _redact(str(item.get("evidence", item.get("summary", ""))), usernames=redact_usernames, ips=redact_ips),
                    "correlation_id": item.get("correlation_id", ""),
                }
            )
        return {
            "generated_at": utc_now_iso(),
            "local_only": True,
            "redact_usernames": redact_usernames,
            "redact_ips": redact_ips,
            "patterns": redacted_patterns,
            "event_timeline": redacted_events,
            "recommended_questions": [
                "What changed first?",
                "Was the activity expected?",
                "What evidence should be preserved before any cleanup?",
                "What surrounding events support or weaken this explanation?",
            ],
            "evidence_gaps": self._evidence_gaps(patterns, findings),
        }

    def _evidence_gaps(self, patterns: list[IntrusionPattern], findings: list[dict[str, Any]]) -> list[str]:
        gaps = []
        if not patterns:
            gaps.append("No correlated intrusion patterns were identified from the current local evidence.")
        if not findings:
            gaps.append("No scan findings are available for cross-checking.")
        if not self.db.recent_background_monitor_events(limit=1):
            gaps.append("No recent monitor events are available.")
        return gaps

    def write_ai_summary(self, summary: dict[str, Any], output_path: Path | None = None) -> Path:
        base = output_path or (self.db.path.parent / "reports" / "ai_summary.json")
        base.parent.mkdir(parents=True, exist_ok=True)
        base.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        return base

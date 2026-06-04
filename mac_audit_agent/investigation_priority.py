from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.models import Finding, ScanResult, utc_now_iso
from mac_audit_agent.storage import AuditDatabase, FindingSuppressionRule, ReviewChecklistItem, safe_int
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer, WorkflowContextWindow


LOGGER = logging.getLogger(__name__)
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}

PERSISTENCE_HINTS = (
    "launchdaemon",
    "launchagent",
    "login item",
    "persistence",
    "startup item",
    "launchctl",
    "plist",
    "daemon",
)
NETWORK_HINTS = (
    "network",
    "port",
    "listener",
    "connection",
    "connected",
    "vpn",
    "dns",
    "gateway",
    "ip address",
    "remote",
    "socket",
    "localhost",
    "websocket",
)
ADMIN_HINTS = (
    "admin",
    "root",
    "wheel",
    "privilege",
    "ssh",
    "screen sharing",
    "remote login",
    "remote management",
    "users & groups",
)
BENIGN_BROWSER_HELPER_HINTS = (
    "browser helper",
    "web content",
    "gpu process",
    "renderer",
    "xpc service",
    "helper",
    "chrome helper",
    "safari helper",
    "opera helper",
    "firefox helper",
    "electron helper",
)
USER_PRESENCE_EVENTS = {
    "display_wake",
    "display_sleep",
    "screen_locked",
    "screen_unlocked",
    "possible_lid_opened",
    "possible_lid_closed",
    "input_activity_resumed_after_idle",
    "input_activity_idle_started",
    "mouse_or_keyboard_activity_after_idle",
    "usb_device_connected",
    "new_usb_device_detected",
    "bluetooth_device_connected",
    "bluetooth_device_disconnected",
    "network_ip_assigned",
    "vpn_connected",
    "launchdaemon_added",
    "launchagent_added",
    "new_admin_user_detected",
}


@dataclass
class InvestigationPriorityItem:
    finding_id: str
    title: str
    rank_score: int
    why_ranked_here: str
    evidence: str
    confidence: str
    recommended_next_action: str
    estimated_investigation_effort: str
    severity: str = "info"
    first_seen: str = ""
    review_state: str = "not reviewed"
    suppressed: bool = False
    suppression_history_count: int = 0
    trust_score_impact: int = 0
    persistence_involvement: bool = False
    network_involvement: bool = False
    admin_involvement: bool = False
    user_presence_correlation: bool = False
    priority_factors: list[str] = field(default_factory=list)
    source_trace: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationPriorityReport:
    generated_at: str
    scan_id: str
    summary: str
    top_3: list[InvestigationPriorityItem] = field(default_factory=list)
    top_10: list[InvestigationPriorityItem] = field(default_factory=list)
    full_queue: list[InvestigationPriorityItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "scan_id": self.scan_id,
            "summary": self.summary,
            "top_3": [item.to_dict() for item in self.top_3],
            "top_10": [item.to_dict() for item in self.top_10],
            "full_queue": [item.to_dict() for item in self.full_queue],
            "counts": {
                "top_3": len(self.top_3),
                "top_10": len(self.top_10),
                "full_queue": len(self.full_queue),
            },
        }


def build_investigation_priority_report_from_scan(
    scan_result: ScanResult | None,
    *,
    review_statuses: dict[tuple[str, str], ReviewChecklistItem] | None = None,
    suppression_rules: list[FindingSuppressionRule] | None = None,
    context_window: WorkflowContextWindow | None = None,
) -> InvestigationPriorityReport:
    now = utc_now_iso()
    if scan_result is None:
        return InvestigationPriorityReport(
            generated_at=now,
            scan_id="",
            summary="No scan is available to rank findings.",
        )

    review_statuses = review_statuses or {}
    suppression_lookup = {rule.fingerprint: rule for rule in (suppression_rules or []) if rule.active}
    if context_window is not None:
        context_events = [moment.to_dict() for moment in context_window.moments if moment.moment_type == "monitor"]
    else:
        context_events = []

    priorities: list[InvestigationPriorityItem] = []
    for finding in scan_result.findings:
        finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else dict(getattr(finding, "__dict__", {}))
        review_state = _review_state_for_finding(finding, review_statuses)
        suppression = suppression_lookup.get(_finding_fingerprint(finding))
        if suppression is None and suppression_rules:
            try:
                suppression = next((rule for rule in suppression_rules if rule.title == finding.title and rule.category == finding.category), None)
            except Exception:
                suppression = None
        item = _priority_item_from_finding(
            finding,
            scan_result=scan_result,
            review_state=review_state,
            suppression=suppression,
            context_events=context_events,
            finding_dict=finding_dict,
        )
        priorities.append(item)

    priorities.sort(
        key=lambda item: (
            -item.rank_score,
            -SEVERITY_RANK.get(item.severity, 0),
            -CONFIDENCE_RANK.get(item.confidence, 0),
            _parse_timestamp(item.first_seen),
            item.title.lower(),
        )
    )
    summary = (
        f"Ranked {len(priorities)} findings by investigative value, weighting persistence, admin changes, network changes, "
        f"unknown devices, trust score decay, and suppression history ahead of severity alone."
    )
    return InvestigationPriorityReport(
        generated_at=now,
        scan_id=scan_result.scan_id,
        summary=summary,
        top_3=priorities[:3],
        top_10=priorities[:10],
        full_queue=priorities,
    )


class InvestigationPriorityEngine:
    def __init__(self, db: AuditDatabase, workflow_layer: InvestigatorWorkflowLayer | None = None) -> None:
        self.db = db
        self.workflow_layer = workflow_layer or InvestigatorWorkflowLayer(db)

    def build_priorities(self, scan_id: str | None = None, *, scan_result: ScanResult | None = None) -> InvestigationPriorityReport:
        scan = scan_result
        if scan is None:
            scan = self.db.get_scan_result(scan_id) if scan_id else self.db.latest_scan_result()
        if scan is None:
            return build_investigation_priority_report_from_scan(None)
        review_statuses: dict[tuple[str, str], ReviewChecklistItem] = {}
        suppression_rules: list[FindingSuppressionRule] = []
        context_window: WorkflowContextWindow | None = None
        try:
            review_statuses = self.db.get_review_statuses(scan.scan_id)
        except Exception as exc:
            LOGGER.exception("Failed to load review statuses for investigation priorities: %s", exc)
        try:
            suppression_rules = self.db.list_finding_suppressions(limit=1000)
        except Exception as exc:
            LOGGER.exception("Failed to load suppression history for investigation priorities: %s", exc)
        try:
            anchor = scan.timestamp or utc_now_iso()
            context_window = self.workflow_layer.build_context_window(
                anchor,
                focus_label="Investigation priorities",
                focus_kind="scan",
                focus_category="scan",
                focus_id=scan.scan_id,
                focus_scan_id=scan.scan_id,
                window_minutes=15,
            )
        except Exception as exc:
            LOGGER.exception("Failed to build context window for investigation priorities: %s", exc)
            context_window = None
        return build_investigation_priority_report_from_scan(
            scan,
            review_statuses=review_statuses,
            suppression_rules=suppression_rules,
            context_window=context_window,
        )


def _priority_item_from_finding(
    finding: Finding,
    *,
    scan_result: ScanResult,
    review_state: str,
    suppression: FindingSuppressionRule | None,
    context_events: list[dict[str, Any]],
    finding_dict: dict[str, Any],
) -> InvestigationPriorityItem:
    blob = _finding_blob(finding_dict)
    factors: list[str] = []
    severity = str(finding.severity or finding_dict.get("severity", "info")).lower()
    confidence = str(finding.confidence or finding_dict.get("confidence", "low")).lower()
    rank_score = SEVERITY_RANK.get(severity, 0) * 8 + CONFIDENCE_RANK.get(confidence, 0) * 4

    persistence = _keyword_hit(blob, PERSISTENCE_HINTS)
    network = _keyword_hit(blob, NETWORK_HINTS)
    admin = _keyword_hit(blob, ADMIN_HINTS) or bool(getattr(finding, "requires_admin", False)) or bool(getattr(finding, "needs_admin_for_followup", False))
    browser_helper = _keyword_hit(blob, BENIGN_BROWSER_HELPER_HINTS)
    unknown_device = _unknown_device_signal(blob, scan_result, network)
    trust_score_impact, trust_reason = _trust_score_impact(finding_dict, scan_result)
    first_seen = _first_seen_value(finding_dict, scan_result)
    recency_bonus, recency_reason = _recency_bonus(first_seen, scan_result.timestamp)
    user_presence_correlation, user_presence_reason = _user_presence_correlation(blob, context_events)

    if finding.kev or finding_dict.get("kev"):
        rank_score += 5
        factors.append("known exploited status increases priority")
    if persistence:
        rank_score += 20
        factors.append("persistence involvement")
    if admin:
        rank_score += 16
        factors.append("admin change involvement")
    if network:
        rank_score += 14
        factors.append("network involvement")
    if unknown_device:
        rank_score += 10
        factors.append("unknown or review-needed device evidence")
    if trust_score_impact:
        rank_score += min(18, max(0, trust_score_impact // 5))
        factors.append(trust_reason)
    if recency_bonus:
        rank_score += recency_bonus
        factors.append(recency_reason)
    if user_presence_correlation:
        rank_score += 8
        factors.append(user_presence_reason)

    suppression_history_count = suppression.matched_count if suppression is not None else 0
    suppressed = bool(suppression and suppression.active)
    if review_state == "not reviewed":
        rank_score += 4
        factors.append("not reviewed yet")
    elif review_state == "needs follow-up":
        rank_score += 2
        factors.append("already flagged for follow-up")
    elif review_state == "reviewed":
        rank_score -= 6
        factors.append("previously reviewed")
    elif review_state in {"false positive", "resolved"}:
        rank_score -= 12
        factors.append(f"previously marked {review_state}")
    if suppressed:
        rank_score -= 10
        factors.append("active suppression exists")
    if suppression_history_count:
        penalty = min(15, suppression_history_count * 2)
        rank_score -= penalty
        factors.append(f"suppression history seen {suppression_history_count} time(s)")
    if browser_helper:
        rank_score -= 14
        factors.append("known browser helper or benign helper pattern")

    if not factors:
        factors.append("baseline severity and confidence only")

    effort = _effort_label(rank_score, persistence=persistence, admin=admin, network=network, trust_score_impact=trust_score_impact, user_presence=user_presence_correlation)
    evidence_parts = [
        finding.evidence_summary.strip() or finding.evidence.strip() or finding_dict.get("evidence_summary", "") or finding_dict.get("evidence", ""),
    ]
    if finding.raw_signal_summary:
        evidence_parts.append(f"Raw signal: {finding.raw_signal_summary}")
    if finding.normalized_signal:
        evidence_parts.append(f"Normalized signal: {finding.normalized_signal}")
    if finding.source_trace:
        evidence_parts.append(f"Source trace: {finding.source_trace}")
    if finding.previous_state or finding.current_state:
        evidence_parts.append(f"State change: {finding.previous_state or 'unknown'} -> {finding.current_state or 'unknown'}")

    recommended = (
        finding.recommended_next_steps.strip()
        or finding.remediation_suggestion.strip()
        or finding_dict.get("recommended_next_steps", "")
        or "Review the item in context and confirm whether it was expected."
    )
    if user_presence_correlation:
        recommended = f"Review the surrounding timeline before acting. {recommended}".strip()
    if suppressed and review_state in {"false positive", "resolved"}:
        recommended = f"Preserve the existing evidence trail and verify the suppression rationale. {recommended}".strip()

    why_ranked_here = "; ".join(factors)
    return InvestigationPriorityItem(
        finding_id=str(finding.id),
        title=str(finding.title),
        rank_score=max(0, int(rank_score)),
        why_ranked_here=why_ranked_here,
        evidence="\n".join(part for part in evidence_parts if part),
        confidence=confidence,
        recommended_next_action=recommended,
        estimated_investigation_effort=effort,
        severity=severity,
        first_seen=first_seen,
        review_state=review_state,
        suppressed=suppressed,
        suppression_history_count=suppression_history_count,
        trust_score_impact=trust_score_impact,
        persistence_involvement=persistence,
        network_involvement=network,
        admin_involvement=admin,
        user_presence_correlation=user_presence_correlation,
        priority_factors=factors,
        source_trace=str(finding.source_trace or finding_dict.get("source_trace", "")),
    )


def _review_state_for_finding(finding: Finding, review_statuses: dict[tuple[str, str], ReviewChecklistItem]) -> str:
    if finding.id and ("finding", finding.id) in review_statuses:
        return str(review_statuses[("finding", finding.id)].review_state)
    finding_id = str(getattr(finding, "finding_id", "") or "")
    if finding_id and ("finding", finding_id) in review_statuses:
        return str(review_statuses[("finding", finding_id)].review_state)
    return "not reviewed"


def _finding_blob(finding_dict: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in [
        "category",
        "title",
        "description",
        "evidence",
        "evidence_summary",
        "command_used",
        "command_or_source",
        "why_this_matters",
        "false_positive_notes",
        "recommended_next_steps",
        "remediation_suggestion",
        "related_process",
        "related_path",
        "related_user",
        "related_network_endpoint",
        "related_url",
        "previous_state",
        "current_state",
        "raw_signal_summary",
        "normalized_signal",
        "source_trace",
    ]:
        value = finding_dict.get(key)
        if value:
            parts.append(str(value))
    return " ".join(parts).lower()


def _keyword_hit(blob: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in blob for keyword in keywords)


def _unknown_device_signal(blob: str, scan_result: ScanResult, network: bool) -> bool:
    if any(term in blob for term in ("unknown device", "new usb", "new bluetooth", "review needed", "new gateway", "new dns", "new host")):
        return True
    network_discovery = scan_result.artifacts.get("network_discovery", {}) if scan_result else {}
    if isinstance(network_discovery, dict):
        if safe_int(network_discovery.get("review_needed_count")) or any(item.get("review_needed") for item in network_discovery.get("devices", []) if isinstance(item, dict)):
            return bool(network)
    return False


def _trust_score_impact(finding_dict: dict[str, Any], scan_result: ScanResult) -> tuple[int, str]:
    candidates: list[int] = []
    blob = _finding_blob(finding_dict)
    artifacts = scan_result.artifacts if scan_result else {}
    for process in artifacts.get("processes", {}).get("all", []):
        if not isinstance(process, dict):
            continue
        path = str(process.get("command_path", "")).lower()
        name = str(process.get("process_name", "")).lower()
        if path and (path in blob or Path(path).name.lower() in blob):
            score = safe_int(process.get("trust_score"))
            if score is not None:
                candidates.append(score)
        elif name and name in blob:
            score = safe_int(process.get("trust_score"))
            if score is not None:
                candidates.append(score)
    for file_issue in artifacts.get("file_issues", []):
        if not isinstance(file_issue, dict):
            continue
        path = str(file_issue.get("path", "")).lower()
        if path and (path in blob or Path(path).name.lower() in blob):
            score = safe_int(file_issue.get("trust_score"))
            if score is not None:
                candidates.append(score)
    if not candidates:
        process_scores = [safe_int(item.get("trust_score")) for item in artifacts.get("processes", {}).get("suspicious", []) if isinstance(item, dict)]
        file_scores = [safe_int(item.get("trust_score")) for item in artifacts.get("file_issues", []) if isinstance(item, dict)]
        candidates = [score for score in [*process_scores, *file_scores] if score is not None]
    if not candidates:
        return 0, "trust score impact unavailable"
    trust_score = min(candidates)
    impact = max(0, 100 - trust_score)
    if trust_score <= 55:
        return impact, f"low trust score ({trust_score})"
    if trust_score <= 70:
        return impact, f"trust score is lower than baseline ({trust_score})"
    return impact, f"trust score deviation observed ({trust_score})"


def _first_seen_value(finding_dict: dict[str, Any], scan_result: ScanResult) -> str:
    candidate = str(finding_dict.get("first_seen", "") or "").strip()
    if candidate:
        return candidate
    candidate = str(finding_dict.get("created_at", "") or "").strip()
    if candidate:
        return candidate
    return str(scan_result.timestamp or utc_now_iso())


def _recency_bonus(first_seen: str, scan_timestamp: str) -> tuple[int, str]:
    seen = _parse_timestamp(first_seen)
    anchor = _parse_timestamp(scan_timestamp or utc_now_iso())
    delta = abs((anchor - seen).total_seconds())
    if delta <= 24 * 3600:
        return 10, "first seen within the last day"
    if delta <= 7 * 24 * 3600:
        return 6, "first seen within the last week"
    if delta <= 30 * 24 * 3600:
        return 2, "first seen within the last month"
    return 0, ""


def _user_presence_correlation(blob: str, context_events: list[dict[str, Any]]) -> tuple[bool, str]:
    if any(term in blob for term in ("screen unlocked", "screen locked", "lid open", "lid closed", "usb", "bluetooth", "vpn", "network ip", "admin user")):
        return True, "the finding itself references a user-presence or device change"
    correlated = [event for event in context_events if str(event.get("title", "")).strip() in USER_PRESENCE_EVENTS or str(event.get("event_type", event.get("title", ""))).strip() in USER_PRESENCE_EVENTS]
    if correlated:
        top = ", ".join(str(event.get("title", event.get("event_type", ""))) for event in correlated[:4] if str(event.get("title", event.get("event_type", ""))))
        return True, f"nearby user/device events observed: {top}"
    return False, ""


def _effort_label(rank_score: int, *, persistence: bool, admin: bool, network: bool, trust_score_impact: int, user_presence: bool) -> str:
    if rank_score >= 70 or sum([persistence, admin, network, trust_score_impact >= 30, user_presence]) >= 3:
        return "High (30-60 min)"
    if rank_score >= 45 or any([persistence, admin, network, trust_score_impact >= 20, user_presence]):
        return "Medium (15-30 min)"
    return "Low (5-15 min)"


def _finding_fingerprint(finding: Finding | dict[str, Any]) -> str:
    if hasattr(finding, "to_dict"):
        payload = finding.to_dict()
    elif isinstance(finding, dict):
        payload = dict(finding)
    else:
        payload = dict(getattr(finding, "__dict__", {}))
    parts = [
        str(payload.get("category", "")),
        str(payload.get("title", "")),
        str(payload.get("evidence", "")),
        str(payload.get("command_used", payload.get("command_or_source", ""))),
    ]
    return "|".join(part.lower().strip() for part in parts)


def _parse_timestamp(value: str) -> datetime:
    candidate = str(value or "").strip()
    if not candidate:
        return datetime.now(timezone.utc)
    candidate = candidate.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

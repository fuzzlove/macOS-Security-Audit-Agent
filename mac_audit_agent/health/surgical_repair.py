"""Explainable, copyable sensor repair planning and outcome transcripts."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


EXTERNAL_REASON_CODES = {
    "PERMISSION_REVOKED",
    "PERMISSION_REQUIRED",
    "ENTITLEMENT_MISSING",
    "SIGNATURE_INVALID",
    "DUPLICATE_INSTANCE",
}


def _text(value: Any, *, limit: int = 4000) -> str:
    rendered = str(value if value not in (None, "") else "not reported").replace("\x00", "")
    return rendered[:limit]


def build_surgical_repair_plan(sensor: dict[str, Any]) -> dict[str, Any]:
    reason_code = _text(sensor.get("reason_code", "UNKNOWN"), limit=128).upper()
    dependencies = [item for item in sensor.get("dependencies", []) if isinstance(item, dict)]
    failed_dependencies = [
        _text(item.get("dependency_id", "unknown"), limit=128)
        for item in dependencies
        if _text(item.get("state", "UNKNOWN"), limit=64).upper() not in {"HEALTHY", "NOT_APPLICABLE"}
    ]
    operator_required = bool(sensor.get("operator_action_required")) or reason_code in EXTERNAL_REASON_CODES
    repairability = "EXTERNAL APPROVAL OR DEPLOYMENT REQUIRED" if operator_required else "BOUNDED AUTOMATIC REPAIR AVAILABLE"
    phases = [
        {"phase": "1 — Preserve", "action": "Capture the current state, reason code, capability loss, dependencies, queue/drop counters, and prior recovery evidence before mutation."},
        {"phase": "2 — Isolate", "action": "Confirm the failing sensor and repair unhealthy required dependencies first; do not restart unrelated healthy sensors."},
        {"phase": "3 — Repair", "action": "Use only the policy-approved recovery level for this reason code and stop if the circuit breaker or restart budget blocks the attempt."},
        {"phase": "4 — Verify", "action": "Run the sensor's bounded functional self-test, collect a new health snapshot, and require lost capabilities to return."},
        {"phase": "5 — Escalate", "action": "If verification fails, retain the exact error and remaining coverage loss for operator or product support review."},
    ]
    return {
        "sensor_id": _text(sensor.get("sensor_id", "unknown"), limit=256),
        "state": _text(sensor.get("state", "UNKNOWN"), limit=64).upper(),
        "health_score": sensor.get("health_score", "not reported"),
        "reason_code": reason_code,
        "reason": _text(sensor.get("reason", "No reason supplied.")),
        "repairability": repairability,
        "operator_action_required": operator_required,
        "failed_dependencies": failed_dependencies,
        "lost_capabilities": [_text(item, limit=256) for item in sensor.get("lost_capabilities", [])],
        "retained_capabilities": [_text(item, limit=256) for item in sensor.get("retained_capabilities", [])],
        "remediation": _text(sensor.get("remediation", "No sensor-specific remediation supplied.")),
        "evidence": {
            "process_alive": sensor.get("process_alive", "not reported"),
            "initialized": sensor.get("initialized", "not reported"),
            "permission_state": _text(sensor.get("permission_state", "UNKNOWN"), limit=64),
            "queue_depth": sensor.get("queue_depth", "not reported"),
            "queue_capacity": sensor.get("queue_capacity", "not reported"),
            "events_dropped_total": sensor.get("events_dropped_total", "not reported"),
            "events_failed_total": sensor.get("events_failed_total", "not reported"),
            "processing_latency_ms": sensor.get("processing_latency_ms", "not reported"),
            "last_process_heartbeat": _text(sensor.get("last_process_heartbeat", "not reported"), limit=128),
            "last_collection_activity": _text(sensor.get("last_collection_activity", "not reported"), limit=128),
            "last_delivery_activity": _text(sensor.get("last_delivery_activity", "not reported"), limit=128),
        },
        "phases": phases,
    }


def render_surgical_repair_transcript(sensor: dict[str, Any], outcome: dict[str, Any] | None = None) -> str:
    plan = build_surgical_repair_plan(sensor)
    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    lines = [
        "MSAA SENSOR SURGICAL REPAIR REPORT",
        f"Generated: {generated}",
        f"Sensor: {plan['sensor_id']}",
        f"Pre-repair state: {plan['state']}",
        f"Health score: {plan['health_score']}",
        f"Reason code: {plan['reason_code']}",
        f"Reason: {plan['reason']}",
        f"Repairability: {plan['repairability']}",
        "",
        "COVERAGE IMPACT",
        "Lost: " + (", ".join(plan["lost_capabilities"]) or "none reported"),
        "Retained: " + (", ".join(plan["retained_capabilities"]) or "none reported"),
        "Failed dependencies: " + (", ".join(plan["failed_dependencies"]) or "none reported"),
        "",
        "DIAGNOSTIC EVIDENCE",
    ]
    lines.extend(f"{key}: {_text(value)}" for key, value in plan["evidence"].items())
    lines += ["", "SURGICAL REPAIR PLAN"]
    lines.extend(f"{item['phase']}: {item['action']}" for item in plan["phases"])
    lines += ["", "SENSOR-SPECIFIC REMEDIATION", plan["remediation"]]
    if outcome is not None:
        recovery = outcome.get("recovery", {}) if isinstance(outcome.get("recovery"), dict) else {}
        self_test = outcome.get("post_recovery_self_test") if isinstance(outcome.get("post_recovery_self_test"), dict) else {}
        lines += [
            "",
            "REPAIR OUTCOME",
            f"Action: {_text(recovery.get('action', 'not attempted'))}",
            f"Attempted: {bool(recovery.get('attempted', False))}",
            f"Recovery succeeded: {bool(recovery.get('succeeded', False))}",
            f"Recovery detail: {_text(recovery.get('detail', 'No detail supplied.'))}",
            f"Operator action required: {bool(recovery.get('requires_operator', False))}",
            f"Post-repair self-test: {'PASSED' if self_test.get('passed') else 'FAILED' if self_test else 'NOT RUN'}",
            f"Self-test ID: {_text(self_test.get('test_id', 'not run'), limit=256)}",
            f"Self-test detail: {_text(self_test.get('reason', 'not run'))}",
            f"Post-repair state: {_text(outcome.get('post_recovery_state', 'UNKNOWN'), limit=64)}",
            "Remaining lost capabilities: " + (", ".join(_text(item, limit=256) for item in outcome.get("remaining_lost_capabilities", [])) or "none reported"),
            f"Verified fully operational: {bool(outcome.get('fully_operational', False))}",
        ]
        trace = outcome.get("repair_trace", [])
        if isinstance(trace, list) and trace:
            lines += ["", "VERBOSE REPAIR TRACE"]
            for step in trace:
                if isinstance(step, dict):
                    lines.append(
                        f"[{_text(step.get('timestamp', 'unknown'), limit=128)}] "
                        f"{_text(step.get('stage', 'stage'), limit=128)} — {_text(step.get('status', 'unknown'), limit=64)} — {_text(step.get('detail', ''))}"
                    )
        errors = outcome.get("errors", [])
        if isinstance(errors, list) and errors:
            lines += ["", "ERRORS / BLOCKERS"]
            lines.extend(f"- {_text(error)}" for error in errors)
    lines += [
        "",
        "SUPPORT NOTE",
        "This transcript is designed to be copied into a support case. It contains bounded operational evidence and does not include credentials or secret command arguments.",
    ]
    return "\n".join(lines) + "\n"


__all__ = ["EXTERNAL_REASON_CODES", "build_surgical_repair_plan", "render_surgical_repair_transcript"]

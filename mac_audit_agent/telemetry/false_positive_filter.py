from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mac_audit_agent.runtime.command_models import CommandOrigin


@dataclass(frozen=True)
class FalsePositiveDecision:
    trusted_internal_activity: bool
    alert_eligible: bool
    severity: str
    event_classification: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "trusted_internal_activity": self.trusted_internal_activity,
            "alert_eligible": self.alert_eligible,
            "severity": self.severity,
            "event_classification": self.event_classification,
            "reason": self.reason,
        }


class FalsePositiveFilter:
    def classify_command_event(self, *, origin: CommandOrigin | str, execution_status: str, anomaly_detected: bool = False) -> FalsePositiveDecision:
        origin_value = origin.value if isinstance(origin, CommandOrigin) else str(origin)
        failed = execution_status not in {"completed"}
        if origin_value == CommandOrigin.INTERNAL_MSAA_TASK.value:
            return FalsePositiveDecision(
                trusted_internal_activity=True,
                alert_eligible=failed or anomaly_detected,
                severity="medium" if failed or anomaly_detected else "low",
                event_classification="trusted_internal_diagnostic" if not failed else "trusted_internal_failure",
                reason="MSAA internal subsystem execution" if not failed else "MSAA internal subsystem execution failed",
            )
        if origin_value == CommandOrigin.SYSTEM_MONITOR.value:
            return FalsePositiveDecision(
                trusted_internal_activity=True,
                alert_eligible=failed or anomaly_detected,
                severity="medium" if failed or anomaly_detected else "info",
                event_classification="system_monitor_health",
                reason="MSAA system monitor execution" if not failed else "MSAA system monitor execution degraded",
            )
        if origin_value == CommandOrigin.USER_INITIATED.value:
            return FalsePositiveDecision(
                trusted_internal_activity=False,
                alert_eligible=True,
                severity="medium" if not failed else "high",
                event_classification="user_initiated_command",
                reason="User initiated command execution",
            )
        if origin_value in {CommandOrigin.DIAGNOSTIC.value, CommandOrigin.REPAIR_WIZARD.value, CommandOrigin.ALERT_PIPELINE.value, CommandOrigin.TEST_FRAMEWORK.value}:
            return FalsePositiveDecision(
                trusted_internal_activity=origin_value != CommandOrigin.USER_INITIATED.value,
                alert_eligible=failed or anomaly_detected,
                severity="medium" if failed or anomaly_detected else "low",
                event_classification=origin_value.lower(),
                reason=f"MSAA {origin_value.lower()} command execution",
            )
        return FalsePositiveDecision(False, True, "medium", "unclassified_command", "Unclassified command origin")


def apply_false_positive_filter(event_payload: dict[str, Any]) -> dict[str, Any]:
    decision = FalsePositiveFilter().classify_command_event(
        origin=str(event_payload.get("origin", "")),
        execution_status=str(event_payload.get("execution_status", "completed")),
        anomaly_detected=bool(event_payload.get("anomaly_detected", False)),
    )
    normalized = dict(event_payload)
    normalized.update(decision.to_dict())
    return normalized

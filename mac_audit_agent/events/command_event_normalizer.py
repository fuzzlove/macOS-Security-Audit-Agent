from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace
from mac_audit_agent.runtime.command_models import CommandExecutionResult, CommandOrigin
from mac_audit_agent.telemetry.false_positive_filter import FalsePositiveDecision, FalsePositiveFilter


@dataclass(frozen=True)
class NormalizedCommandEvent:
    event: BackgroundMonitorEvent
    decision: FalsePositiveDecision


class CommandEventNormalizer:
    def __init__(self, false_positive_filter: FalsePositiveFilter | None = None) -> None:
        self.false_positive_filter = false_positive_filter or FalsePositiveFilter()

    def normalize(self, result: CommandExecutionResult) -> BackgroundMonitorEvent:
        decision = self.false_positive_filter.classify_command_event(
            origin=result.origin,
            execution_status=result.execution_status,
        )
        event_type = self._event_type_for(result.origin, result.execution_status)
        metadata = {
            "origin": result.origin.value,
            "safety_level": result.safety_level.value,
            "command_id": result.command_id,
            "command_hash": result.command_hash,
            "caller_module": result.caller_module,
            "stack_trace_ref": result.stack_trace_ref,
            "duration_ms": result.duration_ms,
            "execution_status": result.execution_status,
            "trusted_internal_activity": decision.trusted_internal_activity,
            "alert_eligible": decision.alert_eligible,
            "classification_reason": decision.reason,
            "event_classification": decision.event_classification,
        }
        return BackgroundMonitorEvent(
            event_id=f"command-event-{result.command_id}",
            timestamp=result.timestamp,
            event_type=event_type,
            severity=decision.severity,
            source="internal_command_executor",
            process_name=result.args[0] if result.args else "",
            evidence=(
                f"Command execution classified as {decision.event_classification}; "
                f"origin={result.origin.value}; command_hash={result.command_hash}; status={result.execution_status}"
            ),
            confidence="high",
            recommendation=self._recommendation_for(result, decision),
            notification_decision="alert_eligible" if decision.alert_eligible else "log_only",
            notification_reason=decision.reason,
            popup_allowed=decision.alert_eligible,
            visible_alert_shown=False,
            alert_style="neutral_grey" if not decision.alert_eligible else decision.severity,
            metadata_json=json.dumps(metadata, sort_keys=True),
            suppression_reason="" if decision.alert_eligible else decision.reason,
            false_positive_hints=[decision.reason] if decision.trusted_internal_activity else [],
            recommended_verification_steps=[
                "Review command origin, caller module, command hash, and execution status in the command audit trail.",
            ],
            source_trace=result.stack_trace_ref,
        )

    def trace_for(self, result: CommandExecutionResult, event: BackgroundMonitorEvent, *, db_path: str = "") -> EventAlertTrace:
        decision = self.false_positive_filter.classify_command_event(
            origin=result.origin,
            execution_status=result.execution_status,
        )
        return EventAlertTrace(
            trace_id=f"trace-{uuid4()}",
            event_id=event.event_id,
            event_type=str(event.event_type),
            original_event_type="command_execution",
            normalized_event_type=str(event.event_type),
            canonical_event_type=str(event.event_type),
            severity=event.severity,
            detector_source="internal_command_executor",
            created_at=result.timestamp,
            stored_db_path=db_path,
            stored_success=True,
            event_written_to_db=True,
            event_db_path=db_path,
            notification_policy_checked=True,
            notification_policy_result="eligible" if decision.alert_eligible else "log_only",
            notification_policy_reason=decision.reason,
            policy_result="eligible" if decision.alert_eligible else "log_only",
            severity_before_policy="medium",
            severity_after_policy=event.severity,
            alert_required=decision.alert_eligible,
            alert_suppressed=not decision.alert_eligible,
            alert_suppression_reason="" if decision.alert_eligible else decision.reason,
        )

    def _event_type_for(self, origin: CommandOrigin, execution_status: str) -> str:
        failed = execution_status != "completed"
        if origin == CommandOrigin.SYSTEM_MONITOR:
            return "system_monitor_command_health_degraded" if failed else "system_monitor_command_health"
        if origin == CommandOrigin.USER_INITIATED:
            return "user_initiated_command_execution"
        if failed:
            return "internal_command_execution_failure"
        return "internal_command_execution"

    def _recommendation_for(self, result: CommandExecutionResult, decision: FalsePositiveDecision) -> str:
        if decision.alert_eligible:
            return "Review the command audit record and related health or integrity context."
        return "No user action required. The command remains logged for audit and forensic traceability."

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum
from typing import Callable

from .models import ProcessIdentity


class ContainmentAction(StrEnum):
    OBSERVE_ONLY = "observe_only"
    PAUSE_EXACT_PROCESS = "pause_exact_process"
    TERMINATE_EXACT_PROCESS = "terminate_exact_process"


@dataclass(frozen=True)
class ContainmentRequest:
    incident_id: str
    expected_identity: ProcessIdentity
    action: ContainmentAction
    expires_at: datetime
    approver: str
    rollback: str
    evidence_id: str
    critical_continuity: bool = False


@dataclass(frozen=True)
class ContainmentResult:
    status: str
    error_code: str
    message: str
    action_performed: bool


def authorize_containment(request: ContainmentRequest, live_identity: ProcessIdentity, *, perform: Callable[[ContainmentAction, ProcessIdentity], bool] | None = None) -> ContainmentResult:
    if request.expires_at.tzinfo is None or request.expires_at <= datetime.now(timezone.utc):
        return ContainmentResult("blocked", "AR034", "Response authorization expired; no process action performed.", False)
    if not request.expected_identity.matches_exact(live_identity):
        return ContainmentResult("blocked", "AR030", "Process identity changed or PID was reused; unsafe response blocked.", False)
    if not request.evidence_id:
        return ContainmentResult("blocked", "AR030", "Evidence must be preserved before containment.", False)
    if request.critical_continuity and request.action is not ContainmentAction.OBSERVE_ONLY:
        return ContainmentResult("blocked", "AR033", "Critical continuity exclusion applied; administrator escalation required.", False)
    if request.action is ContainmentAction.OBSERVE_ONLY:
        return ContainmentResult("observed", "", "Observe-only policy performed no process action.", False)
    if perform is None:
        return ContainmentResult("not_verified", "AR016", "Containment helper is unavailable; no signal was sent.", False)
    ok = perform(request.action, live_identity)
    return ContainmentResult("contained" if ok else "failed", "" if ok else "AR017", "Exact process action verified." if ok else "Containment action could not be verified.", ok)

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso


RepairStatus = Literal["pending", "running", "succeeded", "failed", "skipped"]


@dataclass
class RepairAction:
    action_id: str
    title: str
    component: str
    issue: str
    proposed_fix: str
    requires_admin: bool = False
    destructive: bool = False
    requires_restart: bool = False
    command_preview: str = ""
    status: RepairStatus = "pending"
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    verification_result: str = ""

    @classmethod
    def create(cls, title: str, component: str, issue: str, proposed_fix: str, **kwargs: Any) -> "RepairAction":
        return cls(action_id=f"repair-{uuid4().hex[:12]}", title=title, component=component, issue=issue, proposed_fix=proposed_fix, **kwargs)

    @property
    def safe_to_run_automatically(self) -> bool:
        return not self.requires_admin and not self.destructive

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RepairPlan:
    generated_at: str = field(default_factory=utc_now_iso)
    actions: list[RepairAction] = field(default_factory=list)

    @property
    def safe_actions(self) -> list[RepairAction]:
        return [action for action in self.actions if action.safe_to_run_automatically]

    @property
    def manual_actions(self) -> list[RepairAction]:
        return [action for action in self.actions if not action.safe_to_run_automatically]

    def to_dict(self) -> dict[str, Any]:
        return {"generated_at": self.generated_at, "actions": [action.to_dict() for action in self.actions]}


@dataclass
class RepairResult:
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str = ""
    actions: list[RepairAction] = field(default_factory=list)
    before_status: str = ""
    after_status: str = ""
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

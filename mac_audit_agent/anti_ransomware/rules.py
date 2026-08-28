from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum

from .models import ProcessIdentity


class RuleAction(StrEnum):
    ALLOW_ONCE = "allow_once"
    ALLOW_IDENTITY = "allow_identity"
    ALLOW_BEHAVIOR_WITH_LIMITS = "allow_behavior_with_limits"
    BLOCK_ONCE = "block_once"
    BLOCK_IDENTITY = "block_identity"
    MONITOR_ONLY = "monitor_only"


@dataclass(frozen=True)
class RansomwareRule:
    rule_id: str
    action: RuleAction
    executable_sha256: str
    script_sha256: str = ""
    team_id: str = ""
    signing_id: str = ""
    canonical_path: str = ""
    expires_at: datetime | None = None
    approver: str = ""
    rationale: str = ""
    maximum_file_rate: int | None = None

    def matches(self, identity: ProcessIdentity) -> bool:
        if self.expires_at and self.expires_at <= datetime.now(timezone.utc):
            return False
        if not self.executable_sha256 or self.executable_sha256 != identity.executable_sha256:
            return False
        return all((not expected or expected == observed) for expected, observed in ((self.script_sha256, identity.script_sha256), (self.team_id, identity.team_id), (self.signing_id, identity.signing_id), (self.canonical_path, identity.executable_path)))


def validate_managed_rule(rule: RansomwareRule, identity: ProcessIdentity, *, managed: bool, actor_is_admin: bool, second_approver: str = "") -> None:
    if rule.action in {RuleAction.ALLOW_IDENTITY, RuleAction.BLOCK_IDENTITY} and not rule.rationale.strip():
        raise ValueError("[AR018] Permanent identity rules require a rationale.")
    if managed and (identity.effective_uid == 0 or identity.platform_binary) and not actor_is_admin:
        raise PermissionError("[AR031] Administrator approval is required for a managed root or platform-process rule.")
    if managed and rule.action is RuleAction.ALLOW_IDENTITY and not second_approver:
        raise PermissionError("[AR031] Managed permanent trust requires the configured second approver.")

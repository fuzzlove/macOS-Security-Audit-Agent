from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum
from pathlib import Path


class NotificationState(StrEnum):
    CREATED = "CREATED"; SANITIZED = "SANITIZED"; QUEUED = "QUEUED"
    DELIVERED_TO_NOTIFIER = "DELIVERED_TO_NOTIFIER"; DISPLAY_ATTEMPTED = "DISPLAY_ATTEMPTED"
    DISPLAYED = "DISPLAYED"; ACKNOWLEDGED = "ACKNOWLEDGED"; ACTION_REQUESTED = "ACTION_REQUESTED"
    ACTION_AUTHORIZED = "ACTION_AUTHORIZED"; ACTION_REJECTED = "ACTION_REJECTED"
    ACTION_COMPLETED = "ACTION_COMPLETED"; EXPIRED = "EXPIRED"; DELIVERY_FAILED = "DELIVERY_FAILED"


@dataclass(frozen=True)
class SanitizedNotification:
    notification_id: str; incident_id: str; severity: str; confidence: str
    process_display_name: str; redacted_path: str; affected_file_count: int
    rationale: tuple[str, ...]; containment_state: str; approved_actions: tuple[str, ...]
    expires_at: str; support_contact: str; state: NotificationState = NotificationState.SANITIZED


class PendingNotificationQueue:
    """Sanitized per-user queue; never opens the protected root database."""
    def __init__(self, path: Path, *, max_items: int = 256) -> None:
        self.path = Path(path); self.max_items = max_items
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def enqueue(self, item: SanitizedNotification) -> None:
        items = self.read_all(include_expired=False)
        items.append(replace(item, state=NotificationState.QUEUED))
        items = items[-self.max_items:]
        self.path.write_text(json.dumps([_serialize(x) for x in items], sort_keys=True, indent=2), encoding="utf-8")

    def transition(self, notification_id: str, state: NotificationState) -> SanitizedNotification:
        items = self.read_all(include_expired=True)
        updated = None
        result = []
        for item in items:
            if item.notification_id == notification_id:
                updated = replace(item, state=state)
                result.append(updated)
            else:
                result.append(item)
        if updated is None:
            raise KeyError(notification_id)
        self._write(result)
        return updated

    def replay_pending(self) -> list[SanitizedNotification]:
        pending = {NotificationState.QUEUED, NotificationState.DELIVERY_FAILED, NotificationState.DELIVERED_TO_NOTIFIER, NotificationState.DISPLAY_ATTEMPTED}
        return [item for item in self.read_all(include_expired=False) if item.state in pending]

    def acknowledge(self, notification_id: str) -> SanitizedNotification:
        return self.transition(notification_id, NotificationState.ACKNOWLEDGED)

    def read_all(self, *, include_expired: bool = False) -> list[SanitizedNotification]:
        if not self.path.exists(): return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        now = datetime.now(timezone.utc)
        result = []
        for row in raw:
            item = SanitizedNotification(**(row | {"rationale": tuple(row["rationale"]), "approved_actions": tuple(row["approved_actions"]), "state": NotificationState(row["state"])}))
            expiry = datetime.fromisoformat(item.expires_at.replace("Z", "+00:00"))
            if include_expired or expiry > now: result.append(item)
        return result

    def _write(self, items: list[SanitizedNotification]) -> None:
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps([_serialize(x) for x in items[-self.max_items:]], sort_keys=True, indent=2), encoding="utf-8")
        temporary.replace(self.path)


def _serialize(item: SanitizedNotification) -> dict:
    payload = asdict(item); payload["state"] = item.state.value; return payload

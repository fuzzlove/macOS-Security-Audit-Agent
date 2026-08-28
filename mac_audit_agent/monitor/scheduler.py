from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso


@dataclass
class DetectorSchedule:
    detector_id: str
    interval_seconds: int
    timeout_seconds: int
    expensive: bool = False
    last_run_at: str = ""
    next_run_after: str = ""
    skip_reason: str = ""
    backoff_seconds: int = 0
    jitter_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_DETECTOR_SCHEDULES = {
    "usb_bluetooth": DetectorSchedule("usb_bluetooth", 30, 10, jitter_seconds=5),
    "camera_session_lid": DetectorSchedule("camera_session_lid", 15, 5, jitter_seconds=5),
    "network": DetectorSchedule("network", 60, 15, jitter_seconds=10),
    "persistence_admin": DetectorSchedule("persistence_admin", 300, 45, expensive=True, jitter_seconds=30),
    "rootkit_posture": DetectorSchedule("rootkit_posture", 3600, 120, expensive=True, jitter_seconds=120),
    "apple_exposure": DetectorSchedule("apple_exposure", 21_600, 180, expensive=True, jitter_seconds=300),
    "integrity": DetectorSchedule("integrity", 1800, 120, expensive=True, jitter_seconds=120),
    "operational_health": DetectorSchedule("operational_health", 300, 30, jitter_seconds=30),
}


def should_run_detector(schedule: DetectorSchedule, now_epoch: float, last_run_epoch: float | None) -> tuple[bool, str]:
    if last_run_epoch is None:
        return True, ""
    interval = schedule.interval_seconds + random.randint(0, max(0, schedule.jitter_seconds)) + max(0, schedule.backoff_seconds)
    if now_epoch - last_run_epoch >= interval:
        return True, ""
    return False, "interval_not_elapsed"


def persist_detector_schedule(db: Any, schedules: dict[str, DetectorSchedule] | None = None) -> None:
    payload = {key: value.to_dict() for key, value in (schedules or DEFAULT_DETECTOR_SCHEDULES).items()}
    db.set_background_monitor_state("performance.detector_schedule_json", __import__("json").dumps(payload, sort_keys=True))
    db.set_background_monitor_state("performance.detector_schedule_updated_at", utc_now_iso())

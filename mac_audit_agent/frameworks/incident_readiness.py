from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class DFARSIncident:
    incident_id: str
    discovery_time: str
    affected_contracts: list[str]
    cui_or_cdi_impact: str
    operationally_critical_support_impact: str
    submitted_at: str = ""
    government_submission_authorized: bool = False

    def deadlines(self) -> dict[str, str | int | bool]:
        discovery = datetime.fromisoformat(self.discovery_time)
        report_due = discovery + timedelta(hours=72)
        preservation_due = discovery + timedelta(days=90)
        now = datetime.now(timezone.utc)
        return {"report_due": report_due.isoformat(), "preservation_due": preservation_due.isoformat(), "report_hours_remaining": max(0, int((report_due - now).total_seconds() // 3600)), "report_overdue": now > report_due and not self.submitted_at, "preservation_expired": now > preservation_due}

    def prepare_package(self) -> dict[str, object]:
        return {"incident": asdict(self), "deadlines": self.deadlines(), "submission_performed": False, "submission_endpoint": "DIBNet preparation only", "warning": "MSAA never submits reports or malware automatically; legal, management, and authorized-user review is required."}


__all__ = ["DFARSIncident"]

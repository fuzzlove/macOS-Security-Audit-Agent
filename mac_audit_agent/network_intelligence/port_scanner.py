from __future__ import annotations

from mac_audit_agent.network_intelligence.connection_parser import parse_lsof_listeners
from mac_audit_agent.network_intelligence.models import ListeningPort


class ListeningPortCollector:
    def __init__(self, runner) -> None:
        self.runner = runner

    def collect(self) -> tuple[list[ListeningPort], list[str]]:
        result = self.runner(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if result.returncode != 0:
            return [], [f"lsof listener collection failed: {(result.stderr or result.stdout).strip()}"]
        return parse_lsof_listeners(result.stdout), []

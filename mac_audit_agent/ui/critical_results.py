from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from mac_audit_agent.ui.findings_filter import normalize_severity


def finding_identity(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("finding_id") or finding.get("id") or "").strip()
    if explicit:
        return explicit
    stable = {
        "category": str(finding.get("category", "")),
        "title": str(finding.get("title", "")),
        "evidence": str(finding.get("evidence_summary", finding.get("evidence", ""))),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()[:24]


def critical_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(item) for item in findings if normalize_severity(item.get("severity", "info")) == "critical"]


@dataclass
class PinnedCriticalResults:
    """Retain critical findings through non-authoritative UI refreshes.

    An authoritative completed scan replaces the set, allowing verified
    resolution to clear it. Filters, navigation, and partial refreshes only
    merge findings and can never make a critical item disappear.
    """

    findings_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_scan_id: str = ""

    def update(
        self,
        findings: Iterable[dict[str, Any]],
        *,
        authoritative: bool = False,
        scan_id: str = "",
    ) -> tuple[dict[str, Any], ...]:
        incoming = {finding_identity(item): item for item in critical_findings(findings)}
        if authoritative:
            self.findings_by_id = incoming
            self.source_scan_id = str(scan_id or "")
        else:
            self.findings_by_id.update(incoming)
        return self.current()

    def current(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            sorted(
                (dict(item) for item in self.findings_by_id.values()),
                key=lambda item: (str(item.get("category", "")), str(item.get("title", ""))),
            )
        )

    def clear(self) -> None:
        self.findings_by_id.clear()
        self.source_scan_id = ""


__all__ = ["PinnedCriticalResults", "critical_findings", "finding_identity"]

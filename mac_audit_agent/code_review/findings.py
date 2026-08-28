from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CodeReviewFinding:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    confidence: str
    cwe: str
    cve: str | None
    mitre_attack: tuple[str, ...]
    description: str
    analyst_explanation: str
    impact: dict[str, str]
    exploitability: dict[str, str]
    detection_reason: str
    remediation: dict[str, Any]
    references: tuple[dict[str, str], ...]
    affected_file: str
    line: int
    evidence: str
    compliance: dict[str, tuple[str, ...]] = field(default_factory=dict)
    language: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CodeReviewReport:
    project_path: str
    started_at: str
    completed_at: str
    files_reviewed: int
    findings: tuple[CodeReviewFinding, ...]
    limitations: tuple[str, ...]

    @classmethod
    def create(
        cls,
        project_path: Path,
        *,
        started_at: str,
        files_reviewed: int,
        findings: list[CodeReviewFinding],
        limitations: list[str],
    ) -> "CodeReviewReport":
        return cls(
            str(project_path),
            started_at,
            datetime.now(timezone.utc).isoformat(),
            files_reviewed,
            tuple(findings),
            tuple(limitations),
        )

    def counts(self) -> dict[str, int]:
        output = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            output[finding.severity] = output.get(finding.severity, 0) + 1
        return output

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["summary"] = self.counts()
        return payload

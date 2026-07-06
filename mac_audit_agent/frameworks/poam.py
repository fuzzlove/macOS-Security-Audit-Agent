from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass
class POAMItem:
    poam_id: str
    framework: str
    requirement_id: str
    weakness: str
    risk_level: str
    source_finding_id: str
    recommended_fix: str
    validation_step: str
    owner: str = ""
    target_completion_date: str = ""
    status: str = "Open"
    evidence_needed: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def poam_from_cmmc_readiness(readiness: dict[str, Any]) -> list[POAMItem]:
    items: list[POAMItem] = []
    for gap in readiness.get("top_gaps", []) or []:
        requirement_id = str(gap.get("cmmc_id", gap.get("requirement_id", "")))
        items.append(
            POAMItem(
                poam_id=f"poam-{uuid4().hex[:10]}",
                framework="CMMC",
                requirement_id=requirement_id,
                weakness=str(gap.get("title", "CMMC evidence gap")),
                risk_level="medium" if gap.get("level", 1) < 3 else "high",
                source_finding_id="",
                recommended_fix="Collect missing MSAA evidence and required manual organizational evidence.",
                validation_step="Re-run Framework Readiness and verify evidence status is collected or manual review complete.",
                evidence_needed=", ".join(gap.get("evidence_expectations", []) or []),
                notes="Generated for readiness preparation only; not an assessor determination.",
            )
        )
    for evidence in readiness.get("evidence_items", []) or []:
        if str(evidence.get("evidence_status", "")) in {"missing", "insufficient", "manual_review_required"}:
            items.append(
                POAMItem(
                    poam_id=f"poam-{uuid4().hex[:10]}",
                    framework="CMMC",
                    requirement_id=str(evidence.get("requirement_id", "")),
                    weakness=f"Evidence {evidence.get('evidence_status')} for {evidence.get('source_check_id', '')}",
                    risk_level="medium",
                    source_finding_id=str(evidence.get("source_check_id", "")),
                    recommended_fix=str(evidence.get("recommended_fix", "Collect required evidence.")),
                    validation_step="Attach evidence and rerun readiness mapping.",
                    evidence_needed=str(evidence.get("analyst_note", "")),
                    notes=str(evidence.get("result_summary", "")),
                )
            )
    return items


def export_poam_json(items: list[POAMItem], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([item.to_dict() for item in items], indent=2, sort_keys=True), encoding="utf-8")
    return path


def export_poam_csv(items: list[POAMItem], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(POAMItem.__dataclass_fields__)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in items:
            writer.writerow(item.to_dict())
    return path


__all__ = ["POAMItem", "poam_from_cmmc_readiness", "export_poam_json", "export_poam_csv"]

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class StandardsContentPack:
    pack_id: str
    version: str
    profile_id: str
    source_records: list[dict[str, Any]]
    requirements: list[dict[str, Any]]
    objectives: list[dict[str, Any]]
    parser_version: str
    previous_pack_id: str = ""
    migration_notes: list[str] = field(default_factory=list)
    pack_sha256: str = ""
    human_review_status: str = "NOT_REVIEWED"
    activation_approved_by: str = ""

    def canonical_bytes(self) -> bytes:
        payload = asdict(self)
        payload["pack_sha256"] = ""
        payload["activation_approved_by"] = ""
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def calculate_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def validate_activation(self, *, expected_requirements: int, expected_objectives: int | None) -> dict[str, Any]:
        gates = {
            "official_sources": bool(self.source_records) and all(item.get("official_domain") and item.get("document_sha256") for item in self.source_records),
            "schema_valid": bool(self.pack_id and self.version and self.profile_id and self.parser_version),
            "requirement_count": len({item.get("requirement_id") for item in self.requirements}) == expected_requirements,
            "objective_count": expected_objectives is None or len({item.get("objective_id") for item in self.objectives}) == expected_objectives,
            "identifiers": all(item.get("requirement_id") for item in self.requirements) and all(item.get("objective_id") and item.get("requirement_id") for item in self.objectives),
            "cross_references": {item.get("requirement_id") for item in self.objectives} <= {item.get("requirement_id") for item in self.requirements},
            "human_review": self.human_review_status == "APPROVED",
            "migration_impact": bool(self.migration_notes) or not self.previous_pack_id,
            "tests_validated": False,
            "explicit_activation": bool(self.activation_approved_by),
            "hash_matches": bool(self.pack_sha256) and self.pack_sha256 == self.calculate_hash(),
        }
        return {"activatable": all(gates.values()), "gates": gates, "error_code": "" if all(gates.values()) else "STD005"}

    def write(self, path: Path) -> dict[str, str]:
        self.pack_sha256 = self.calculate_hash()
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"
        path.write_text(content, encoding="utf-8")
        return {"path": str(path), "sha256": hashlib.sha256(content.encode()).hexdigest(), "content_pack_sha256": self.pack_sha256}


def load_pack(path: Path) -> StandardsContentPack:
    return StandardsContentPack(**json.loads(path.read_text(encoding="utf-8")))


__all__ = ["StandardsContentPack", "load_pack"]

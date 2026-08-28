from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.integrity.signing import calculate_file_sha256


@dataclass(slots=True)
class TwoPassHashVerificationResult:
    status: str
    pass_one_count: int
    pass_two_count: int
    mismatches: list[str] = field(default_factory=list)
    failure_stage: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def verify_manifest_two_pass(root: Path, manifest_path: Path) -> TwoPassHashVerificationResult:
    root = Path(root).resolve(strict=False)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    entries = [entry for entry in manifest.get("files", []) if isinstance(entry, dict)]
    pass_one = _hash_entries(root, entries)
    pass_two = _hash_entries(root, entries)
    mismatches = [rel for rel in sorted(set(pass_one) | set(pass_two)) if pass_one.get(rel) != pass_two.get(rel)]
    if mismatches:
        return TwoPassHashVerificationResult("failed", len(pass_one), len(pass_two), mismatches, "nondeterministic_hashing_detected")
    manifest_mismatches = [rel for rel, observed in pass_two.items() if observed != _expected(entries, rel)]
    if manifest_mismatches:
        return TwoPassHashVerificationResult("failed", len(pass_one), len(pass_two), manifest_mismatches, "source_changed_during_signing")
    return TwoPassHashVerificationResult("verified", len(pass_one), len(pass_two))


def _hash_entries(root: Path, entries: list[dict]) -> dict[str, str]:
    result = {}
    for entry in entries:
        rel = str(entry.get("relative_path", ""))
        if not rel:
            continue
        path = root / rel
        if path.exists() and path.is_file():
            result[rel] = calculate_file_sha256(path)
        else:
            result[rel] = ""
    return result


def _expected(entries: list[dict], rel: str) -> str:
    for entry in entries:
        if entry.get("relative_path") == rel:
            return str(entry.get("sha256", ""))
    return ""


__all__ = ["TwoPassHashVerificationResult", "verify_manifest_two_pass"]

"""Evidence-disciplined ATT&CK mappings for observed ransomware behavior."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique: str
    tactic: str
    confidence: str
    evidence: tuple[str, ...]
    inference: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


MAPPINGS = {
    "encryption_burst": ("T1486", "Data Encrypted for Impact", "Impact"),
    "mass_deletion": ("T1485", "Data Destruction", "Impact"),
    "recovery_tamper": ("T1490", "Inhibit System Recovery", "Impact"),
    "defense_tamper": ("T1562.001", "Impair Defenses", "Defense Evasion"),
    "script_rewrite_burst": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "launch_agent": ("T1543.001", "Launch Agent", "Persistence"),
    "launch_daemon": ("T1543.004", "Launch Daemon", "Persistence"),
    "directory_discovery": ("T1083", "File and Directory Discovery", "Discovery"),
    "archive_workflow": ("T1560", "Archive Collected Data", "Collection"),
    "supported_exfiltration": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
}


def map_behaviors(behaviors: Iterable[str], evidence: dict[str, Iterable[str]] | None = None) -> list[MitreMapping]:
    evidence = evidence or {}
    output: list[MitreMapping] = []
    for behavior in behaviors:
        if behavior not in MAPPINGS:
            continue
        facts = tuple(str(item) for item in evidence.get(behavior, ()))
        if behavior == "supported_exfiltration" and not facts:
            continue
        technique_id, technique, tactic = MAPPINGS[behavior]
        output.append(MitreMapping(technique_id, technique, tactic, "high" if len(facts) >= 2 else "medium" if facts else "low", facts, not bool(facts)))
    return output


__all__ = ["MAPPINGS", "MitreMapping", "map_behaviors"]

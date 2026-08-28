"""Deterministic, non-destructive validation of ransomware behavior rules."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from mac_audit_agent.models import utc_now_iso

from .behavior_engine import BehaviorSignal, RansomwareBehaviorEngine
from .enhanced_detection import FileTransition, transition_signals
from .models import DetectionSignal, FileStatistics
from .risk_engine import decide
from .sabotage import CommandObservation, sabotage_signals
from .simulator import synthetic_fixture_signals

RULESET_VERSION = "ransomware-safe-simulation-2.0"


def _statistics(*, entropy: float, size: int = 4096, sampled: int | None = None) -> FileStatistics:
    return FileStatistics(
        size=size,
        entropy=entropy,
        chi_square=0.0,
        monte_carlo_pi_error=0.0,
        base64_ratio=0.0,
        recognized_image=False,
        gzip_header=False,
        bytes_sampled=size if sampled is None else sampled,
    )


LOW_ENTROPY = _statistics(entropy=3.2)
HIGH_ENTROPY = _statistics(entropy=7.95)
LARGE_HIGH_ENTROPY = _statistics(entropy=7.98, size=64 * 1024 * 1024, sampled=1024 * 1024)


def _transition(**flags: bool) -> list[DetectionSignal]:
    after = LARGE_HIGH_ENTROPY if flags.pop("large", False) else HIGH_ENTROPY
    return transition_signals(FileTransition(LOW_ENTROPY, after, "synthetic", **flags))


def _synthetic(*identifiers: str) -> list[DetectionSignal]:
    selected = set(identifiers)
    return [signal for signal in synthetic_fixture_signals() if signal.signal_id in selected]


def _sabotage(executable: str, arguments: tuple[str, ...], *, maintenance: bool = False) -> list[DetectionSignal]:
    return sabotage_signals(CommandObservation(executable, arguments, approved_maintenance=maintenance))


@dataclass(frozen=True)
class RansomwareSimulationDefinition:
    simulation_id: str
    title: str
    behavior: str
    definition_sources: tuple[str, ...]
    required_signal_ids: tuple[str, ...]
    build_signals: Callable[[], list[DetectionSignal]]
    expected_minimum_score: int = 40
    category: str = "FILE_MUTATION"
    expected_outcome: str = "CAUGHT"
    expected_maximum_score: int | None = None

    def public_metadata(self) -> dict[str, object]:
        return {
            "simulation_id": self.simulation_id,
            "title": self.title,
            "behavior": self.behavior,
            "definition_sources": list(self.definition_sources),
            "required_signal_ids": list(self.required_signal_ids),
            "expected_minimum_score": self.expected_minimum_score,
            "expected_maximum_score": self.expected_maximum_score,
            "expected_outcome": self.expected_outcome,
            "category": self.category,
            "safe_mode": "in_memory_rule_evaluation",
        }


def _combine(*builders: Callable[[], list[DetectionSignal]]) -> Callable[[], list[DetectionSignal]]:
    def build() -> list[DetectionSignal]:
        combined: list[DetectionSignal] = []
        seen: set[str] = set()
        for builder in builders:
            for signal in builder():
                if signal.signal_id not in seen:
                    combined.append(signal)
                    seen.add(signal.signal_id)
        return combined

    return build


TRANSITION_SOURCE = "anti_ransomware.enhanced_detection.transition_signals"
SABOTAGE_SOURCE = "anti_ransomware.sabotage.sabotage_signals"
BURST_SOURCE = "anti_ransomware.simulator.synthetic_fixture_signals"


SIMULATION_CATALOG: tuple[RansomwareSimulationDefinition, ...] = (
    RansomwareSimulationDefinition(
        "AR-SIM-01", "Rapid write and entropy burst", "A bounded write burst is followed by high-entropy rewrites.",
        (BURST_SOURCE, TRANSITION_SOURCE), ("synthetic_write_burst", "high_entropy_transition"),
        _combine(lambda: _synthetic("synthetic_write_burst"), lambda: _transition()), 85,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-02", "Encrypted-extension replacement", "Content becomes high entropy while its extension changes and a replacement is renamed over it.",
        (TRANSITION_SOURCE,), ("high_entropy_transition", "extension_changed", "rename_over_original"),
        lambda: _transition(extension_changed=True, rename_over_original=True), 60,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-03", "Original deleted after rewrite", "A high-entropy replacement is produced and the original is removed.",
        (TRANSITION_SOURCE, BURST_SOURCE), ("high_entropy_transition", "original_deleted", "synthetic_write_burst"),
        _combine(lambda: _transition(original_deleted=True), lambda: _synthetic("synthetic_write_burst")), 90,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-04", "Protected canary changed", "An approved synthetic canary changes alongside an entropy transition.",
        (TRANSITION_SOURCE,), ("protected_canary_modified", "high_entropy_transition"),
        lambda: _transition(canary=True), 90,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-05", "Ransom-note pattern after write burst", "A benign ransom-note marker follows rapid disposable writes.",
        (TRANSITION_SOURCE, BURST_SOURCE), ("ransom_note_pattern", "synthetic_write_burst"),
        _combine(lambda: _transition(ransom_note=True), lambda: _synthetic("synthetic_write_burst")), 85,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-06", "Snapshot deletion intent plus writes", "Synthetic command telemetry resembles snapshot deletion before a write burst; no command executes.",
        (SABOTAGE_SOURCE, BURST_SOURCE), ("snapshot_deletion_attempt", "synthetic_write_burst"),
        _combine(lambda: _sabotage("tmutil", ("deletelocalsnapshots", "TEST")), lambda: _synthetic("synthetic_write_burst")), 95,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-07", "Backup targeting with file replacement", "Snapshot-deletion intent correlates with entropy change and deletion of an original.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE), ("snapshot_deletion_attempt", "high_entropy_transition", "original_deleted"),
        _combine(lambda: _sabotage("tmutil", ("delete", "TEST")), lambda: _transition(original_deleted=True)), 90,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-08", "Protection service impairment", "Synthetic launchctl intent targets the MSAA service before rapid writes; launchctl is never invoked.",
        (SABOTAGE_SOURCE, BURST_SOURCE), ("protection_service_impairment", "synthetic_write_burst"),
        _combine(lambda: _sabotage("launchctl", ("disable", "system/com.macauditagent.monitor")), lambda: _synthetic("synthetic_write_burst")), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-09", "Protection impairment and canary change", "A protection-impairment signal correlates with a modified protected canary.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE), ("protection_service_impairment", "protected_canary_modified"),
        _combine(lambda: _sabotage("launchctl", ("bootout", "system/com.macauditagent.monitor")), lambda: _transition(canary=True)), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-10", "Evidence tamper and entropy rewrite", "Synthetic command intent targets protected evidence while files transition to high entropy.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE), ("protection_or_evidence_tamper", "high_entropy_transition"),
        _combine(lambda: _sabotage("sh", ("rm ", "anti_ransomware", "evidence")), lambda: _transition()), 80,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-11", "Integrity tamper and ransom note", "Integrity-manifest tamper intent correlates with rapid writes and a ransom-note pattern.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE, BURST_SOURCE),
        ("protection_or_evidence_tamper", "synthetic_write_burst", "ransom_note_pattern"),
        _combine(
            lambda: _sabotage("sh", ("unlink", "integrity_manifest")),
            lambda: _synthetic("synthetic_write_burst"),
            lambda: _transition(ransom_note=True),
        ), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-12", "Atomic replacement chain", "An extension change, entropy increase, original deletion, and rename-over-original occur together.",
        (TRANSITION_SOURCE,),
        ("high_entropy_transition", "extension_changed", "original_deleted", "rename_over_original"),
        lambda: _transition(extension_changed=True, original_deleted=True, rename_over_original=True), 75,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-13", "Canary and ransom-note correlation", "A protected canary change occurs with a ransom-note filename pattern.",
        (TRANSITION_SOURCE,), ("protected_canary_modified", "ransom_note_pattern"),
        lambda: _transition(canary=True, ransom_note=True), 85,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-14", "Large-file bounded analysis", "A sampled large file changes to high entropy during a rapid write wave.",
        (TRANSITION_SOURCE, BURST_SOURCE), ("large_file_sampled", "high_entropy_transition", "synthetic_write_burst"),
        _combine(lambda: _transition(large=True), lambda: _synthetic("synthetic_write_burst")), 90,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-15", "Approved maintenance still correlated", "Approved maintenance lowers snapshot risk but does not erase a correlated write burst and note pattern.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE, BURST_SOURCE),
        ("snapshot_deletion_attempt", "synthetic_write_burst", "ransom_note_pattern"),
        _combine(
            lambda: _sabotage("tmutil", ("deletelocalsnapshots", "TEST"), maintenance=True),
            lambda: _synthetic("synthetic_write_burst"),
            lambda: _transition(ransom_note=True),
        ), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-16", "Multi-stage ransomware composite", "Protection impairment, snapshot targeting, canary modification, and entropy change form a high-confidence composite.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE),
        ("protection_service_impairment", "snapshot_deletion_attempt", "protected_canary_modified", "high_entropy_transition"),
        _combine(
            lambda: _sabotage("launchctl", ("unload", "com.macauditagent.monitor")),
            lambda: _sabotage("tmutil", ("delete", "TEST")),
            lambda: _transition(canary=True),
        ), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-17", "Rename-delete encryption chain", "An entropy transition is combined with extension change, original deletion, and rename-over-original.",
        (TRANSITION_SOURCE,), ("high_entropy_transition", "extension_changed", "original_deleted", "rename_over_original"),
        lambda: _transition(extension_changed=True, original_deleted=True, rename_over_original=True), 75,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-18", "Canary, note, and write wave", "A rapid write wave reaches a protected canary and is followed by a ransom-note pattern.",
        (BURST_SOURCE, TRANSITION_SOURCE), ("synthetic_write_burst", "protected_canary_modified", "ransom_note_pattern"),
        _combine(lambda: _synthetic("synthetic_write_burst"), lambda: _transition(canary=True, ransom_note=True)), 100,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-19", "Backup and protection suppression", "Snapshot deletion intent and protection-service impairment occur in one synthetic sequence.",
        (SABOTAGE_SOURCE,), ("snapshot_deletion_attempt", "protection_service_impairment"),
        _combine(
            lambda: _sabotage("tmutil", ("deletelocalsnapshots", "TEST")),
            lambda: _sabotage("launchctl", ("disable", "system/com.macauditagent.monitor")),
        ), 100, "DEFENSE_EVASION",
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-20", "Evidence tamper before replacement", "Evidence-tamper intent precedes a high-entropy atomic replacement.",
        (SABOTAGE_SOURCE, TRANSITION_SOURCE), ("protection_or_evidence_tamper", "high_entropy_transition", "rename_over_original"),
        _combine(
            lambda: _sabotage("sh", ("unlink", "anti_ransomware", "evidence")),
            lambda: _transition(rename_over_original=True),
        ), 100, "DEFENSE_EVASION",
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-21", "Extension wave and ransom note", "A rapid write burst correlates with an extension change and ransom-note pattern.",
        (BURST_SOURCE, TRANSITION_SOURCE), ("synthetic_write_burst", "extension_changed", "ransom_note_pattern"),
        _combine(lambda: _synthetic("synthetic_write_burst"), lambda: _transition(extension_changed=True, ransom_note=True)), 95,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-22", "Large-file replacement chain", "Bounded large-file analysis identifies entropy, deletion, and rename-over-original signals.",
        (TRANSITION_SOURCE,), ("large_file_sampled", "high_entropy_transition", "original_deleted", "rename_over_original"),
        lambda: _transition(large=True, original_deleted=True, rename_over_original=True), 75,
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-23", "Snapshot and evidence destruction", "Backup-deletion intent correlates with attempts to remove anti-ransomware evidence.",
        (SABOTAGE_SOURCE,), ("snapshot_deletion_attempt", "protection_or_evidence_tamper"),
        _combine(
            lambda: _sabotage("tmutil", ("delete", "TEST")),
            lambda: _sabotage("sh", ("rm ", "anti_ransomware", "evidence")),
        ), 95, "DEFENSE_EVASION",
    ),
    RansomwareSimulationDefinition(
        "AR-SIM-24", "Full defensive stress chain", "Write burst, backup targeting, protection impairment, canary modification, entropy, and ransom-note context converge.",
        (BURST_SOURCE, SABOTAGE_SOURCE, TRANSITION_SOURCE),
        ("synthetic_write_burst", "snapshot_deletion_attempt", "protection_service_impairment", "protected_canary_modified", "high_entropy_transition", "ransom_note_pattern"),
        _combine(
            lambda: _synthetic("synthetic_write_burst"),
            lambda: _sabotage("tmutil", ("delete", "TEST")),
            lambda: _sabotage("launchctl", ("bootout", "system/com.macauditagent.monitor")),
            lambda: _transition(canary=True, ransom_note=True),
        ), 100, "COMPOSITE",
    ),
    RansomwareSimulationDefinition(
        "AR-CTRL-01", "Ordinary extension rename", "A single low-entropy extension rename should remain below the ransomware threshold.",
        (TRANSITION_SOURCE,), ("extension_changed",),
        lambda: transition_signals(FileTransition(LOW_ENTROPY, LOW_ENTROPY, "synthetic", extension_changed=True)),
        0, "NEGATIVE_CONTROL", "NOT_ESCALATED", 39,
    ),
    RansomwareSimulationDefinition(
        "AR-CTRL-02", "Approved snapshot maintenance", "An isolated approved maintenance action should not be treated as a ransomware chain.",
        (SABOTAGE_SOURCE,), ("snapshot_deletion_attempt",),
        lambda: _sabotage("tmutil", ("deletelocalsnapshots", "TEST"), maintenance=True),
        0, "NEGATIVE_CONTROL", "NOT_ESCALATED", 39,
    ),
    RansomwareSimulationDefinition(
        "AR-CTRL-03", "Isolated note-like filename", "A lone benign note marker without write, entropy, or deletion context should not escalate.",
        (TRANSITION_SOURCE,), ("ransom_note_pattern",),
        lambda: transition_signals(FileTransition(LOW_ENTROPY, LOW_ENTROPY, "synthetic", ransom_note=True)),
        0, "NEGATIVE_CONTROL", "NOT_ESCALATED", 39,
    ),
    RansomwareSimulationDefinition(
        "AR-CTRL-04", "Large pre-compressed file sample", "Sampling an already high-entropy large file should not look like a new encryption transition.",
        (TRANSITION_SOURCE,), ("large_file_sampled",),
        lambda: transition_signals(FileTransition(HIGH_ENTROPY, LARGE_HIGH_ENTROPY, "synthetic")),
        0, "NEGATIVE_CONTROL", "NOT_ESCALATED", 39,
    ),
)


def catalog_metadata() -> list[dict[str, object]]:
    return [scenario.public_metadata() for scenario in SIMULATION_CATALOG]


def run_simulation_suite(selected_ids: set[str] | None = None) -> dict[str, object]:
    """Evaluate scenarios in memory; never execute command telemetry or touch files."""
    known = {scenario.simulation_id for scenario in SIMULATION_CATALOG}
    selected = known if selected_ids is None else {str(value) for value in selected_ids}
    unknown = selected - known
    if unknown:
        raise ValueError(f"Unknown ransomware simulation IDs: {', '.join(sorted(unknown))}")
    engine = RansomwareBehaviorEngine()
    results: list[dict[str, object]] = []
    for scenario in SIMULATION_CATALOG:
        if scenario.simulation_id not in selected:
            continue
        signals = scenario.build_signals()
        reason_codes = {signal.signal_id for signal in signals}
        decision = decide(signals)
        behavioral = engine.evaluate([
            BehaviorSignal(
                signal.signal_id,
                min(0.99, 0.55 + signal.weight / 200.0),
                signal.weight,
                signal.rationale,
                dict(signal.evidence),
                high_confidence=signal.weight >= 35,
            )
            for signal in signals
        ])
        required_present = set(scenario.required_signal_ids).issubset(reason_codes)
        detected = required_present and decision.score >= scenario.expected_minimum_score
        if scenario.expected_outcome == "NOT_ESCALATED":
            passed = required_present and decision.score <= int(scenario.expected_maximum_score or 39)
            result_name = "CONTROL_PASS" if passed else "UNEXPECTED_ESCALATION"
        else:
            passed = detected
            result_name = "CAUGHT" if passed else "MISSED"
        results.append({
            **scenario.public_metadata(),
            "result": result_name,
            "passed": passed,
            "actual_score": decision.score,
            "severity": decision.severity,
            "confidence": decision.confidence,
            "risk_state": behavioral.risk_state.value,
            "threat_state": behavioral.to_dict()["threat_state"],
            "recommended_response": decision.recommended_response,
            "automatic_response_eligible": decision.automatic_response_eligible,
            "observed_signals": [asdict(signal) for signal in signals],
            "missing_required_signals": sorted(set(scenario.required_signal_ids) - reason_codes),
            "containment_performed": False,
        })
    catalog_hash = hashlib.sha256(json.dumps(catalog_metadata(), sort_keys=True).encode()).hexdigest()
    report: dict[str, object] = {
        "operation": "safe_ransomware_definition_simulation_suite",
        "generated_at": utc_now_iso(),
        "ruleset_version": RULESET_VERSION,
        "catalog_sha256": catalog_hash,
        "simulation_mode": True,
        "definition_evaluation": "built_in_behavior_definitions",
        "external_malware_hash_or_yara_claim": False,
        "scenario_count": len(results),
        "attack_scenario_count": sum(item["expected_outcome"] == "CAUGHT" for item in results),
        "negative_control_count": sum(item["expected_outcome"] == "NOT_ESCALATED" for item in results),
        "caught_count": sum(item["expected_outcome"] == "CAUGHT" and bool(item["passed"]) for item in results),
        "missed_count": sum(item["expected_outcome"] == "CAUGHT" and not bool(item["passed"]) for item in results),
        "control_passed_count": sum(item["expected_outcome"] == "NOT_ESCALATED" and bool(item["passed"]) for item in results),
        "unexpected_escalation_count": sum(item["expected_outcome"] == "NOT_ESCALATED" and not bool(item["passed"]) for item in results),
        "passed_count": sum(bool(item["passed"]) for item in results),
        "failed_count": sum(not bool(item["passed"]) for item in results),
        "all_passed": all(bool(item["passed"]) for item in results),
        "results": results,
        "safety": {
            "filesystem_writes": False,
            "commands_executed": False,
            "processes_spawned": False,
            "network_access": False,
            "backup_changes": False,
            "security_controls_changed": False,
            "containment_performed": False,
        },
        "qualification": (
            "This validates deterministic rule evaluation, not live Endpoint Security delivery, active containment, "
            "or matches from the current external YARA/hash release."
        ),
    }
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report


def export_simulation_report(report: dict[str, object], destination: Path) -> Path:
    destination = Path(destination)
    if destination.suffix.lower() != ".json":
        raise ValueError("Ransomware simulation reports use the .json extension.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    return destination


__all__ = [
    "RULESET_VERSION",
    "SIMULATION_CATALOG",
    "RansomwareSimulationDefinition",
    "catalog_metadata",
    "export_simulation_report",
    "run_simulation_suite",
]

from __future__ import annotations

import json
import signal
import stat
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.remediation.evidence import collect_keylogger_evidence
from mac_audit_agent.remediation.keylogger_remediation import KeyloggerAuditLog, KeyloggerRemediationEngine
from mac_audit_agent.remediation.quarantine import quarantine_path, restore_quarantine


def _finding(path: Path, *, score: int = 90) -> dict:
    return {
        "finding_id": "test-keylogger",
        "title": "Suspicious Keyboard Monitor",
        "score": score,
        "confidence": "high",
        "process_name": path.name,
        "path": str(path),
        "signals": ["Uses CGEventTap", "unsigned binary", "network beacon detected"],
        "evidence": {"signature": {"valid": False, "team_id": "", "authority": ""}},
    }


def test_assessment_requires_evidence_before_high_impact_action(tmp_path: Path) -> None:
    target = tmp_path / "monitor"
    target.write_text("fixture", encoding="utf-8")
    engine = KeyloggerRemediationEngine(
        evidence_root=tmp_path / "evidence",
        quarantine_root=tmp_path / "quarantine",
        audit_log=KeyloggerAuditLog(tmp_path / "audit.jsonl"),
    )

    assessment = engine.assess(_finding(target))

    assert assessment.threat_score >= 85
    assert assessment.severity == "critical"
    assert assessment.protected is False
    assert assessment.recommended_action.startswith("Quarantine")


def test_low_confidence_item_cannot_be_quarantined(tmp_path: Path) -> None:
    target = tmp_path / "accessibility-helper"
    target.write_text("fixture", encoding="utf-8")
    engine = KeyloggerRemediationEngine(
        evidence_root=tmp_path / "evidence",
        quarantine_root=tmp_path / "quarantine",
        audit_log=KeyloggerAuditLog(tmp_path / "audit.jsonl"),
    )
    finding = _finding(target, score=10)
    finding["signals"] = ["Accessibility permission"]
    finding["evidence"] = {"signature": {"valid": True, "team_id": "TEAMID", "authority": "Developer ID"}}

    with pytest.raises(PermissionError, match="below the quarantine threshold"):
        engine.quarantine(finding)

    assert target.exists()


def test_high_false_positive_risk_blocks_high_impact_intervention(tmp_path: Path) -> None:
    target = tmp_path / "signed-accessibility-tool"
    target.write_text("fixture", encoding="utf-8")
    finding = _finding(target, score=90)
    finding["false_positive_risk_percent"] = 80
    engine = KeyloggerRemediationEngine(
        evidence_root=tmp_path / "evidence",
        quarantine_root=tmp_path / "quarantine",
        audit_log=KeyloggerAuditLog(tmp_path / "audit.jsonl"),
    )

    assessment = engine.assess(finding)
    assert assessment.false_positive_risk_percent == 80
    with pytest.raises(PermissionError, match="false-positive risk"):
        engine.quarantine(finding)
    assert target.exists()


def test_quarantine_is_non_executable_and_reversible(tmp_path: Path) -> None:
    target = tmp_path / "collector"
    target.write_text("fixture", encoding="utf-8")
    target.chmod(0o755)

    manifest = quarantine_path(target, finding=_finding(target), root=tmp_path / "quarantine")
    quarantined = Path(manifest["quarantine_path"])

    assert not target.exists()
    assert quarantined.exists()
    assert quarantined.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0

    restored = restore_quarantine(quarantined.parent / "manifest.json")
    assert restored["restored"] is True
    assert target.exists()
    assert target.stat().st_mode & stat.S_IXUSR


def test_unhook_terminates_verified_owner_and_quarantines_reversibly(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "keyboard-monitor"
    target.write_text("fixture", encoding="utf-8")
    target.chmod(0o755)
    finding = _finding(target)
    finding["pid"] = 4242
    engine = KeyloggerRemediationEngine(
        evidence_root=tmp_path / "evidence",
        quarantine_root=tmp_path / "quarantine",
        audit_log=KeyloggerAuditLog(tmp_path / "audit.jsonl"),
    )
    signals: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(engine, "_process_is_running", lambda _pid: True)
    monkeypatch.setattr(engine, "_revalidate_process", lambda _pid, _path: None)
    monkeypatch.setattr("mac_audit_agent.remediation.keylogger_remediation.os.kill", lambda pid, sig: signals.append((pid, sig)))

    result = engine.unhook_and_quarantine(finding)

    assert result["status"] == "unhooked_and_quarantined"
    assert result["hook_release"] == "termination_requested"
    assert result["permanent_deletion"] is False
    assert signals == [(4242, signal.SIGTERM)]
    assert not target.exists()
    assert Path(result["quarantined"][-1]["quarantine_path"]).exists()


def test_unhook_refuses_low_confidence_permission_only_item(tmp_path: Path) -> None:
    target = tmp_path / "accessibility-helper"
    target.write_text("fixture", encoding="utf-8")
    finding = _finding(target, score=10)
    finding["signals"] = ["Accessibility permission"]
    finding["evidence"] = {"signature": {"valid": True, "team_id": "TEAMID", "authority": "Developer ID"}}
    engine = KeyloggerRemediationEngine(
        evidence_root=tmp_path / "evidence",
        quarantine_root=tmp_path / "quarantine",
        audit_log=KeyloggerAuditLog(tmp_path / "audit.jsonl"),
    )

    with pytest.raises(PermissionError, match="below the unhook threshold"):
        engine.unhook_and_quarantine(finding)

    assert target.exists()


def test_evidence_snapshot_is_bounded_and_manifested(tmp_path: Path) -> None:
    target = tmp_path / "collector"
    target.write_text("fixture", encoding="utf-8")

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "sanitized output", "")

    incident = collect_keylogger_evidence(_finding(target), root=tmp_path / "evidence", runner=runner)

    assert (incident / "finding.json").is_file()
    assert (incident / "process_snapshot.json").is_file()
    manifest = json.loads((incident / "manifest.sha256.json").read_text(encoding="utf-8"))
    assert "finding.json" in manifest
    assert json.loads((incident / "binary_hashes.json").read_text(encoding="utf-8"))["sha256"]


def test_audit_log_forms_hash_chain(tmp_path: Path) -> None:
    target = tmp_path / "collector"
    target.write_text("fixture", encoding="utf-8")
    log = KeyloggerAuditLog(tmp_path / "remediation.jsonl")
    finding = _finding(target)

    first = log.append(finding=finding, action="investigate", target=str(target), result="success")
    second = log.append(finding=finding, action="quarantine", target=str(target), result="refused")

    assert second["previous_hash"] == first["record_hash"]
    assert second["record_hash"] != first["record_hash"]

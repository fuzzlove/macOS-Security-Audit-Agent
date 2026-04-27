import json
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from mac_audit_agent.models import Finding, InvestigationNote, ScanSummary
from mac_audit_agent.storage import AuditDatabase, json_safe, normalize_finding_for_db, normalize_finding_payload


def make_summary(scan_id: str = "scan-1") -> ScanSummary:
    return ScanSummary(
        scan_id=scan_id,
        started_at="2026-04-23T00:00:00Z",
        completed_at="2026-04-23T00:01:00Z",
        findings_count=1,
        security_score=80,
        notes="test",
        new_items_count=0,
    )


def make_finding() -> Finding:
    return Finding(
        id="finding-1",
        category="Network",
        title="Listener",
        severity="high",
        description="desc",
        evidence={"port": 8080},
        command_used="lsof -nP -iTCP -sTCP:LISTEN",
        remediation_suggestion="Review the process.",
        warning="May disrupt a legitimate service.",
        false_positive_notes="Could be a local dev tool.",
        recommended_next_steps="Verify the listener owner before disabling it.",
        what_can_go_wrong="Stopping the wrong service can interrupt work.",
        remediation_steps=["Review process", "Disable only if unexpected"],
        remediation_commands=["launchctl print system/example"],
        remediation_risk="sensitive",
        requires_admin=True,
        reversible=True,
        estimated_impact="medium",
        verification_steps=["Re-run the scan"],
    )


def test_normalize_finding_payload_old_recommendation_loads_successfully() -> None:
    normalized = normalize_finding_payload(
        {
            "id": "f-1",
            "category": "Legacy",
            "title": "Legacy Finding",
            "severity": "medium",
            "description": "desc",
            "evidence": "evidence",
            "recommendation": "do this",
            "command": "legacy command",
        }
    )
    assert normalized["recommended_next_steps"] == "do this"
    assert normalized["command_or_source"] == "legacy command"
    assert normalized["command_used"] == "legacy command"


def test_normalize_finding_payload_ignores_unknown_extra_field() -> None:
    normalized = normalize_finding_payload(
        {
            "id": "f-2",
            "category": "Legacy",
            "title": "Extra",
            "severity": "low",
            "description": "desc",
            "evidence": "evidence",
            "unexpected_field": "ignore me",
        }
    )
    assert "unexpected_field" not in normalized


def test_normalize_finding_payload_missing_optional_fields_get_defaults() -> None:
    normalized = normalize_finding_payload(
        {
            "id": "f-3",
            "category": "Legacy",
            "title": "Minimal",
            "severity": "info",
            "description": "desc",
            "evidence": "evidence",
        }
    )
    assert normalized["command_used"]
    assert normalized["recommended_next_steps"]
    assert normalized["what_can_go_wrong"]
    assert normalized["remediation_references"] == []
    assert normalized["created_at"]


def test_corrupt_finding_does_not_crash_app_startup(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_scan(make_summary())
    payload = {
        "schema_version": 1,
        "scan_id": "scan-1",
        "timestamp": "2026-04-23T00:01:00Z",
        "hostname": "host.local",
        "current_user": "m",
        "findings": [
            "not-a-dict",
            {
                "id": "f-legacy",
                "category": "Legacy",
                "title": "Old",
                "severity": "medium",
                "description": "desc",
                "evidence": "evidence",
                "recommendation": "review",
            },
        ],
        "raw_logs": [],
        "collected_artifacts": {},
        "baseline_diff": {},
        "errors": [],
    }
    db.conn.execute(
        "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
        ("scan-1", json.dumps(payload)),
    )
    db.conn.commit()

    result = db.latest_scan_result()

    assert result is not None
    assert len(result.findings) == 2
    assert any(finding.title == "Saved Finding Could Not Be Loaded" for finding in result.findings)
    assert any(finding.title == "Old" for finding in result.findings)


def test_latest_scan_result_returns_none_if_db_payload_is_bad_json(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_scan(make_summary())
    db.conn.execute(
        "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
        ("scan-1", "{not valid json"),
    )
    db.conn.commit()

    assert db.latest_scan_result() is None


def test_latest_scan_result_partial_result_safely_if_legacy_payload_has_extra_fields(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_scan(make_summary())
    payload = {
        "schema_version": 1,
        "scan_id": "scan-1",
        "timestamp": "2026-04-23T00:01:00Z",
        "hostname": "host.local",
        "current_user": "m",
        "findings": [
            {
                "id": "f-1",
                "category": "Legacy",
                "title": "Old Finding",
                "severity": "high",
                "description": "desc",
                "evidence": "evidence",
                "recommendation": "review",
                "command": "old command",
                "extra": "ignored",
            }
        ],
        "raw_logs": [],
        "collected_artifacts": {},
        "baseline_diff": {},
        "errors": [],
    }
    db.conn.execute(
        "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
        ("scan-1", json.dumps(payload)),
    )
    db.conn.commit()

    result = db.latest_scan_result()

    assert result is not None
    assert len(result.findings) == 1
    assert result.findings[0].recommended_next_steps == "review"
    assert result.findings[0].command_or_source == "old command"


def test_loading_old_db_payload_with_dry_exit_code_does_not_crash(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_scan(make_summary())
    payload = {
        "schema_version": 1,
        "scan_id": "scan-1",
        "timestamp": "2026-04-23T00:01:00Z",
        "hostname": "host.local",
        "current_user": "m",
        "findings": [],
        "raw_logs": [
            {
                "collector_name": "ports",
                "command_or_source": "lsof",
                "timestamp": "2026-04-23T00:01:00Z",
                "exit_code": "DRY",
                "stderr_summary": "",
                "stdout_summary": "Command skipped",
            }
        ],
        "collected_artifacts": {
            "command_results": [
                {
                    "command_id": "network.listening_ports",
                    "command_preview": "lsof -nP -iTCP -sTCP:LISTEN",
                    "executed_at": "2026-04-23T00:01:00Z",
                    "stdout": "",
                    "stderr": "",
                    "exit_code": "DRY",
                    "timed_out": False,
                    "truncated": False,
                    "dry_run": True,
                }
            ],
            "ports": [
                {
                    "process_name": "python3",
                    "pid": "DRY",
                    "local_address": "127.0.0.1:8888",
                    "port": "DRY",
                    "protocol": "TCP",
                    "state": "LISTEN",
                }
            ],
            "process_snapshots": [
                {
                    "pid": "DRY",
                    "ppid": "DRY",
                    "user": "m",
                    "command_path": "/tmp/tool",
                    "process_name": "tool",
                    "signed_status": "unknown",
                    "trust_level": "review",
                    "reasons": [],
                }
            ],
        },
        "baseline_diff": {},
        "errors": [],
    }
    db.conn.execute(
        "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
        ("scan-1", json.dumps(payload)),
    )
    db.conn.commit()

    result = db.latest_scan_result()

    assert result is not None
    assert result.raw_logs[0].exit_code is None
    assert result.collected_artifacts["command_results"][0].exit_code is None
    assert result.collected_artifacts["ports"]["listening"][0].pid is None


def test_json_safe_serializes_ipaddress_and_paths(tmp_path: Path) -> None:
    value = {
        "network": ipaddress.IPv4Network("192.168.1.0/24"),
        "address": ipaddress.IPv4Address("192.168.1.20"),
        "interface": ipaddress.IPv4Interface("192.168.1.20/24"),
        "timestamp": datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc),
        "items": (1, 2, {3}),
        "path": tmp_path / "discoveries",
    }
    safe = json_safe(value)
    assert safe["network"] == "192.168.1.0/24"
    assert safe["address"] == "192.168.1.20"
    assert safe["interface"] == "192.168.1.20/24"
    assert safe["timestamp"] == "2026-04-26T12:00:00+00:00"
    assert safe["items"] == [1, 2, [3]]
    assert safe["path"] == str(tmp_path / "discoveries")


def test_record_network_discovery_normalizes_payload(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    payload = {
        "interface": "en0",
        "subnet": ipaddress.IPv4Network("192.168.1.0/24"),
        "gateway_ip": ipaddress.IPv4Address("192.168.1.1"),
        "hosts": [
            {
                "ip_address": ipaddress.IPv4Address("192.168.1.20"),
                "likely_hostname": "Johns-MacBook-Pro.local",
                "first_seen": datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc),
                "last_seen": datetime(2026, 4, 26, 12, 1, 0, tzinfo=timezone.utc),
                "discovery_methods": ("arp", "mdns"),
                "review_flags": {"new device"},
            }
        ],
        "comparison": {},
        "debug_logs": [],
        "errors": [],
    }

    db.record_network_discovery("scan-1", payload)
    latest = db.latest_network_discovery()

    assert latest is not None
    assert latest["subnet"] == "192.168.1.0/24"
    assert latest["gateway_ip"] == "192.168.1.1"
    assert latest["devices"][0].ip_address == "192.168.1.20"
    assert latest["devices"][0].discovery_methods == ["arp", "mdns"]


def test_create_and_edit_investigation_note(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    note = InvestigationNote(
        note_id="note-1",
        created_at="2026-04-26T00:00:00Z",
        updated_at="2026-04-26T00:00:00Z",
        title="Initial Note",
        body="First pass review.",
        linked_finding_id="finding-1",
        linked_scan_id="scan-1",
        status="open",
        priority="high",
    )
    db.save_investigation_note(note)
    note.body = "Edited body"
    note.updated_at = "2026-04-26T00:01:00Z"
    db.save_investigation_note(note)
    saved = db.list_investigation_notes(linked_scan_id="scan-1", linked_finding_id="finding-1")
    assert len(saved) == 1
    assert saved[0].body == "Edited body"


def test_mark_review_states_and_progress(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_review_status(item_type="finding", item_key="finding-1", label="Finding 1", review_state="reviewed", linked_scan_id="scan-1", linked_finding_id="finding-1")
    db.set_review_status(item_type="finding", item_key="finding-2", label="Finding 2", review_state="false positive", linked_scan_id="scan-1", linked_finding_id="finding-2")
    db.set_review_status(item_type="finding", item_key="finding-3", label="Finding 3", review_state="confirmed concern", linked_scan_id="scan-1", linked_finding_id="finding-3")
    progress = db.investigation_progress("scan-1", 5)
    assert progress["reviewed_count"] == 1
    assert progress["false_positives"] == 1
    assert progress["confirmed_concerns"] == 1
    assert progress["unreviewed_count"] == 2
    assert progress["progress_percentage"] == 60


def test_notes_reload_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite"
    db = AuditDatabase(path, tmp_path / "logs")
    db.save_investigation_note(
        InvestigationNote(
            note_id="note-reload",
            created_at="2026-04-26T00:00:00Z",
            updated_at="2026-04-26T00:00:00Z",
            title="Reload",
            body="Persistent note",
            linked_scan_id="scan-1",
        )
    )
    reopened = AuditDatabase(path, tmp_path / "logs")
    notes = reopened.list_investigation_notes(linked_scan_id="scan-1")
    assert len(notes) == 1
    assert notes[0].title == "Reload"


def test_remediation_logs_are_stored(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_remediation_action(
        scan_id="scan-1",
        finding_id="finding-1",
        action_type="copy",
        command_text="launchctl print system/test",
        explanation="Review the service first.",
        user_approval=True,
        approval_text="COPY",
        result_text="copied to clipboard",
        exit_code=None,
        created_at="2026-04-24T00:00:00Z",
    )

    snapshot = db.export_snapshot()

    assert snapshot["remediation_actions"]
    assert snapshot["remediation_actions"][0]["command_text"] == "launchctl print system/test"
    assert snapshot["remediation_actions"][0]["result_text"] == "copied to clipboard"


def test_record_finding_column_value_counts_match() -> None:
    sql = AuditDatabase.RECORD_FINDING_SQL
    columns_match = re.search(r"INSERT OR REPLACE INTO findings \((.*?)\)\s*VALUES", sql, re.S)
    values_match = re.search(r"VALUES \((.*?)\)", sql, re.S)
    assert columns_match is not None
    assert values_match is not None
    columns = [item.strip() for item in columns_match.group(1).split(",") if item.strip()]
    placeholders = re.findall(r":[a-zA-Z_][a-zA-Z0-9_]*", values_match.group(1))
    payload = normalize_finding_for_db("scan-1", make_finding())
    assert len(columns) == len(placeholders) == len(payload)


def test_record_finding_with_remediation_fields(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_finding("scan-1", make_finding())

    row = db.conn.execute("SELECT * FROM findings WHERE scan_id = ?", ("scan-1",)).fetchone()

    assert row is not None
    assert row["finding_id"] == "finding-1"
    assert json.loads(row["remediation_steps"]) == ["Review process", "Disable only if unexpected"]
    assert json.loads(row["remediation_commands"]) == ["launchctl print system/example"]
    assert json.loads(row["verification_steps"]) == ["Re-run the scan"]


def test_record_finding_with_legacy_finding(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    legacy = {
        "id": "legacy-1",
        "title": "Legacy",
        "severity": "medium",
        "category": "Legacy",
        "description": "desc",
        "evidence": "legacy evidence",
        "recommendation": "review",
        "command": "old command",
    }
    db.record_finding("scan-1", normalize_finding_payload(legacy))

    row = db.conn.execute("SELECT * FROM findings WHERE finding_id = ?", ("legacy-1",)).fetchone()

    assert row is not None
    assert row["recommendation"] == "review"
    assert row["command_or_source"] == "old command"


def test_record_finding_with_dict(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_finding(
        "scan-1",
        {
            "id": "dict-1",
            "title": "Dict finding",
            "severity": "low",
            "category": "Test",
            "description": "desc",
            "evidence": {"path": "/tmp/example"},
            "command_or_source": "manual review",
            "recommended_next_steps": "Review it.",
        },
    )

    row = db.conn.execute("SELECT * FROM findings WHERE finding_id = ?", ("dict-1",)).fetchone()

    assert row is not None
    assert row["evidence"] == json.dumps({"path": "/tmp/example"})


def test_record_finding_does_not_crash_on_extra_fields(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_finding(
        "scan-1",
        {
            "id": "extra-1",
            "title": "Extra finding",
            "severity": "info",
            "category": "Test",
            "description": "desc",
            "evidence": "ok",
            "extra_field": "ignored",
        },
    )

    row = db.conn.execute("SELECT * FROM findings WHERE finding_id = ?", ("extra-1",)).fetchone()

    assert row is not None
    assert row["title"] == "Extra finding"

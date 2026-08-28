from __future__ import annotations

from pathlib import Path

from mac_audit_agent.models import LaunchItemSnapshot
from mac_audit_agent.native_event_bridge import NativeEventFrame, native_event_frame_to_event
from mac_audit_agent.persistence_monitor import PersistenceMonitor, PersistenceSnapshot


def _launch(path: str, content_hash: str) -> LaunchItemSnapshot:
    return LaunchItemSnapshot(
        path=path,
        label=Path(path).stem,
        program="/usr/bin/true",
        program_arguments=["/usr/bin/true"],
        run_at_load=True,
        content_sha256=content_hash,
    )


def test_existing_launch_item_content_change_and_removal_are_alerted() -> None:
    monitor = PersistenceMonitor()
    previous = PersistenceSnapshot(
        timestamp="2026-07-15T12:00:00+00:00",
        launch_items=[_launch("/Library/LaunchDaemons/com.example.changed.plist", "old"), _launch("/Library/LaunchAgents/com.example.removed.plist", "old")],
    )
    current = PersistenceSnapshot(
        timestamp="2026-07-15T12:05:00+00:00",
        launch_items=[_launch("/Library/LaunchDaemons/com.example.changed.plist", "new")],
    )

    events = monitor.evaluate(previous, current)

    by_type = {event.event_type: event for event in events}
    assert by_type["persistence_item_modified"].severity == "high"
    assert "com.example.changed.plist" in by_type["persistence_item_modified"].evidence
    assert by_type["persistence_item_removed"].severity == "medium"
    assert "com.example.removed.plist" in by_type["persistence_item_removed"].evidence


def test_privileged_helper_add_modify_remove_lifecycle(tmp_path: Path, monkeypatch) -> None:
    helper_root = tmp_path / "PrivilegedHelperTools"
    helper_root.mkdir()
    monkeypatch.setattr(
        "mac_audit_agent.persistence_monitor.PERSISTENCE_ARTIFACT_LOCATIONS",
        (("privileged_helper", str(helper_root)),),
    )
    monitor = PersistenceMonitor(executor=lambda command: (1, "", "unavailable"))
    empty = monitor.collect_snapshot()

    helper = helper_root / "com.example.helper"
    helper.write_bytes(b"version-one")
    added = monitor.collect_snapshot()
    add_event = monitor.evaluate(empty, added)[0]
    assert add_event.event_type == "persistence_artifact_added"
    assert add_event.severity == "critical"
    assert add_event.related_path == str(helper)

    helper.write_bytes(b"version-two")
    modified = monitor.collect_snapshot()
    modify_event = monitor.evaluate(added, modified)[0]
    assert modify_event.event_type == "persistence_artifact_modified"
    assert modify_event.severity == "critical"

    helper.unlink()
    removed = monitor.collect_snapshot()
    remove_event = monitor.evaluate(modified, removed)[0]
    assert remove_event.event_type == "persistence_artifact_removed"
    assert remove_event.severity == "medium"


def test_native_persistence_inventory_is_exposed_in_snapshot(tmp_path: Path, monkeypatch) -> None:
    cron_root = tmp_path / "tabs"
    cron_root.mkdir()
    (cron_root / "alice").write_text("@reboot /usr/local/bin/job\n", encoding="utf-8")
    monkeypatch.setattr(
        "mac_audit_agent.persistence_monitor.PERSISTENCE_ARTIFACT_LOCATIONS",
        (("cron_job", str(cron_root)),),
    )

    monitor = PersistenceMonitor(executor=lambda command: (1, "", "unavailable"))
    inventory = monitor.summarize_inventory(monitor.collect_snapshot())

    assert inventory["persistence_artifacts"][0]["mechanism"] == "cron_job"
    assert inventory["persistence_artifacts"][0]["path"].endswith("/alice")


def test_native_persistence_event_retains_bounded_attribution_context() -> None:
    payload = {
        "event_type": "launchdaemon_modified",
        "source": "endpoint_security_sensor",
        "process_name": "installer",
        "process_arguments": ["installer", "-pkg", "/tmp/example.pkg"],
        "process_ancestry": [{"pid": 10, "name": "launchd"}, {"pid": 20, "name": "installer"}],
        "process_signing_id": "com.apple.installer",
        "process_team_id": "APPLE",
        "process_platform_binary": True,
        "related_path": "/Library/LaunchDaemons/com.example.plist",
        "evidence": {"action": "write"},
    }

    frame = NativeEventFrame.from_payload(payload)
    event = native_event_frame_to_event(frame)

    assert event.related_process == "installer"
    assert event.related_path.endswith("com.example.plist")
    assert '"process_signing_id": "com.apple.installer"' in event.metadata_json
    assert '"process_ancestry"' in event.metadata_json


def test_artifact_inventory_is_bounded(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "many"
    root.mkdir()
    for index in range(125):
        (root / f"item-{index:03d}").write_text("x", encoding="utf-8")
    monkeypatch.setattr(
        "mac_audit_agent.persistence_monitor.PERSISTENCE_ARTIFACT_LOCATIONS",
        (("cron_job", str(root)),),
    )

    snapshot = PersistenceMonitor(executor=lambda command: (1, "", "unavailable")).collect_snapshot()

    assert len(snapshot.artifacts) == 100


def test_single_legacy_autorun_file_is_monitored(tmp_path: Path, monkeypatch) -> None:
    loginwindow = tmp_path / "com.apple.loginwindow.plist"
    loginwindow.write_text("LoginHook", encoding="utf-8")
    monkeypatch.setattr(
        "mac_audit_agent.persistence_monitor.PERSISTENCE_ARTIFACT_LOCATIONS",
        (("login_hook_config", str(loginwindow)),),
    )

    snapshot = PersistenceMonitor(executor=lambda command: (1, "", "unavailable")).collect_snapshot()

    assert len(snapshot.artifacts) == 1
    assert snapshot.artifacts[0].mechanism == "login_hook_config"
    assert snapshot.artifacts[0].path == str(loginwindow)


def test_authorized_key_change_is_critical_and_cvss_enriched(tmp_path: Path, monkeypatch) -> None:
    key_file = tmp_path / "authorized_keys"
    monkeypatch.setattr("mac_audit_agent.persistence_monitor.PERSISTENCE_ARTIFACT_LOCATIONS", (("ssh_authorized_key", str(key_file)),))
    monitor = PersistenceMonitor(executor=lambda command: (1, "", "unavailable"))
    before = monitor.collect_snapshot()
    key_file.write_text("ssh-ed25519 AAAATEST analyst\n", encoding="utf-8")
    after = monitor.collect_snapshot()
    event = monitor.evaluate(before, after)[0]
    payload = __import__("json").loads(event.metadata_json)
    assert event.severity == "critical"
    assert payload["cvss_score"] == 9.5
    assert payload["mitre_attack_mapping"] == ["T1098.004"]
    assert payload["sha256"] == after.artifacts[0].content_sha256

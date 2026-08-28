from pathlib import Path

from mac_audit_agent.runtime.topology import SYSTEM_DB, evaluate_runtime_health, resolve_runtime_topology


def test_system_mode_uses_canonical_event_database(tmp_path: Path) -> None:
    settings = tmp_path / "settings.sqlite3"
    topology = resolve_runtime_topology(settings, selected_mode="system", actual_installed_mode="system", home=tmp_path)
    assert topology.canonical_event_database == str(SYSTEM_DB)
    assert topology.settings_storage_database == str(settings)
    assert topology.notifier_event_database == str(SYSTEM_DB)
    assert topology.alert_trace_database == str(tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "alert_receipts.sqlite3")
    assert topology.alert_trace_database != topology.settings_storage_database
    assert topology.acknowledgement_store == topology.alert_trace_database
    assert topology.receipt_producer == "system_monitor"
    assert topology.receipt_consumer == "user_notifier"
    assert topology.notifier_requires_elevated_privileges is False
    assert topology.aligned is True


def test_user_mode_uses_user_database(tmp_path: Path) -> None:
    database = tmp_path / "user.sqlite3"
    topology = resolve_runtime_topology(database, selected_mode="user", actual_installed_mode="user", home=tmp_path)
    assert topology.canonical_event_database == str(database)
    assert topology.notifier_event_database == str(database)


def test_source_and_frozen_program_arguments(tmp_path: Path) -> None:
    source = resolve_runtime_topology(tmp_path / "db", selected_mode="system", frozen=False, executable="/venv/bin/python", home=tmp_path)
    frozen = resolve_runtime_topology(tmp_path / "db", selected_mode="system", frozen=True, executable="/Applications/MSAA.app/Contents/MacOS/MSAA", home=tmp_path)
    assert source.monitor_program_arguments[:3] == ("/venv/bin/python", "-m", "mac_audit_agent.monitor")
    assert frozen.monitor_program_arguments == ("/Applications/MSAA.app/Contents/MacOS/MSAA", "--system-monitor-service")
    assert "python" not in " ".join(frozen.notifier_program_arguments).lower()


def test_notifier_mismatch_and_conflict_are_stable_errors(tmp_path: Path) -> None:
    topology = resolve_runtime_topology(
        tmp_path / "settings.sqlite3",
        selected_mode="system",
        actual_installed_mode="conflict",
        notifier_event_database=tmp_path / "wrong.sqlite3",
    )
    assert topology.aligned is False
    assert {"ALT001", "MON005"}.issubset(topology.error_codes)


def test_separate_receipt_store_does_not_create_source_mismatch(tmp_path: Path) -> None:
    topology = resolve_runtime_topology(tmp_path / "settings.sqlite3", selected_mode="system", actual_installed_mode="system", home=tmp_path)
    assert topology.notifier_receipt_database != topology.canonical_event_database
    assert topology.aligned is True


def test_absent_unloaded_stopped_and_stale_daemon_codes(tmp_path: Path) -> None:
    topology = resolve_runtime_topology(tmp_path / "settings", selected_mode="system", actual_installed_mode="system")
    absent = evaluate_runtime_health(topology, monitor_installed=False, monitor_loaded=False, monitor_running=False)
    unloaded = evaluate_runtime_health(topology, monitor_installed=True, monitor_loaded=False, monitor_running=False)
    stopped = evaluate_runtime_health(topology, monitor_installed=True, monitor_loaded=True, monitor_running=False)
    assert "MON001" in absent.error_codes
    assert "MON002" in unloaded.error_codes
    assert "MON003" in stopped.error_codes
    assert "MON004" in stopped.error_codes

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.app import main as gui_main
from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.cve_radar import CveRadarEngine
from mac_audit_agent.launch_agent import LaunchAgentManager, default_monitor_db_path
from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace, ScanResult, ScanSummary, utc_now_iso
from mac_audit_agent.notification_manager import MANDATORY_VISIBLE_ALERT_EVENT_TYPES, NotificationManager
from mac_audit_agent.operational_health import OperationalHealthEngine
from mac_audit_agent.reliability import ReleaseReadinessEngine
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.rules import canonical_event_type
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness


def _default_db_path() -> Path:
    return Path.home() / ".mac_audit_agent.sqlite3"


def _logs_dir_for_db(db_path: Path) -> Path:
    default_db = _default_db_path()
    if db_path.expanduser() == default_db:
        return AuditConfig().logs_dir
    return db_path.expanduser().resolve().parent / "mac_audit_agent_logs"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="macos-security-audit-agent",
        description="macOS Security Audit Agent local audit, report, and health CLI.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--safe-scan", action="store_true", help="Run a safe read-only local audit scan.")
    mode.add_argument("--aggressive-scan", action="store_true", help="Run the opt-in aggressive local audit scan.")
    parser.add_argument("--report", type=Path, help="Write an HTML report to this path. Uses the requested scan or the latest saved scan.")
    parser.add_argument("--json-report", type=Path, help="Write a JSON report to this path. Uses the requested scan or the latest saved scan.")
    parser.add_argument("--system-health", action="store_true", help="Print operational health as JSON.")
    parser.add_argument("--release-readiness", action="store_true", help="Print release readiness dashboard checks as JSON.")
    parser.add_argument("--release-readiness-expensive", action="store_true", help="Include pytest and compileall in release readiness checks.")
    parser.add_argument("--release-pytest-python", default=None, help="Python executable to use for the release readiness pytest gate.")
    parser.add_argument("--verify-event-flow", action="store_true", help="Run system monitor event-flow verification and print JSON evidence.")
    parser.add_argument("--event-flow-timeout", type=int, default=10, help="Seconds to wait for system monitor event-flow verification.")
    parser.add_argument("--monitor-db", type=Path, default=default_monitor_db_path("system"), help="Shared monitor database for system monitor verification.")
    parser.add_argument("--verify-visible-alert", action="store_true", help="Dispatch a synthetic mandatory event through the visible alert overlay path and print JSON evidence.")
    parser.add_argument("--visible-alert-event-type", default="lid_opened", help="Mandatory event type to use with --verify-visible-alert.")
    parser.add_argument("--verify-clean-install", action="store_true", help="Create a clean venv, install the local wheel, and print JSON release evidence.")
    parser.add_argument("--clean-install-python", type=Path, default=Path(sys.executable), help="Python 3.10+ interpreter to use with --verify-clean-install.")
    parser.add_argument("--clean-install-wheel", type=Path, default=None, help="Wheel path to install. Defaults to the newest dist/*.whl.")
    parser.add_argument("--db", type=Path, default=_default_db_path(), help="SQLite database path. Defaults to ~/.mac_audit_agent.sqlite3.")
    parser.add_argument("--no-gui", action="store_true", help="Do not launch the GUI when no action flags are provided.")
    return parser


def _scan_summary(collectors: CollectorSuite, scan_result: ScanResult, *, started_at: str, scan_mode: str) -> ScanSummary:
    score = collectors.compute_security_score(scan_result.findings)
    return ScanSummary(
        scan_id=scan_result.scan_id,
        started_at=started_at,
        completed_at=utc_now_iso(),
        findings_count=len(scan_result.findings),
        security_score=score,
        notes=f"{scan_mode.title()} macOS audit run from CLI.",
        new_items_count=sum(len(value) for value in scan_result.baseline_diff.values() if isinstance(value, list)),
        score_label=collectors.score_label(score),
    )


def _persist_scan(db: AuditDatabase, summary: ScanSummary, scan_result: ScanResult, *, scan_mode: str, localhost_protocol: str) -> None:
    db.record_scan(summary)
    db.record_scan_result(scan_result)
    for result in scan_result.artifacts.get("command_results", []):
        db.record_command_log(scan_result.scan_id, result)
    for finding in scan_result.findings:
        db.record_finding(scan_result.scan_id, finding)
    db.record_snapshots(
        scan_result.scan_id,
        ports=scan_result.artifacts.get("ports", {}).get("listening", []),
        users=scan_result.artifacts.get("users", []),
        history_indicators=scan_result.artifacts.get("history_indicators", []),
        permissions=scan_result.artifacts.get("permission_snapshots", []),
        files=scan_result.artifacts.get("file_issues", []),
        processes=scan_result.artifacts.get("processes", {}).get("all", []),
        launch_snapshots=scan_result.artifacts.get("launch_snapshots", []),
        launch_items=set(scan_result.artifacts.get("launch_items", [])),
    )
    db.write_scan_logs(
        scan_result.scan_id,
        {
            "findings": scan_result.findings,
            "command_results": scan_result.artifacts.get("command_results", []),
            "ports": scan_result.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}),
            "localhost_scan": scan_result.artifacts.get(
                "localhost_scan",
                {"target": "127.0.0.1", "mode": scan_mode, "protocol": localhost_protocol, "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
            ),
            "processes": scan_result.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []}),
            "users": scan_result.artifacts.get("users", []),
            "history_indicators": scan_result.artifacts.get("history_indicators", []),
            "permission_snapshots": scan_result.artifacts.get("permission_snapshots", []),
            "file_issues": scan_result.artifacts.get("file_issues", []),
            "launch_snapshots": scan_result.artifacts.get("launch_snapshots", []),
            "comparison": type("BaselineHolder", (), {"to_dict": lambda self_: scan_result.baseline_diff})(),
            "raw_logs": scan_result.raw_logs,
        },
    )


def _run_scan(db: AuditDatabase, *, aggressive: bool) -> tuple[ScanSummary, ScanResult]:
    scan_mode = "aggressive" if aggressive else "safe"
    localhost_protocol = "both" if aggressive else "tcp"
    config = AuditConfig(logs_dir=db.logs_dir, dry_run=False, disable_aggressive_scan=False)
    runner = SafeCommandRunner(RunnerConfig(dry_run=False))
    collectors = CollectorSuite(runner, config)
    started_at = utc_now_iso()
    scan_result = collectors.run_scan(
        previous_result=db.latest_scan_result(),
        scan_mode=scan_mode,
        localhost_scan_protocol=localhost_protocol,
    )
    summary = _scan_summary(collectors, scan_result, started_at=started_at, scan_mode=scan_mode)
    _persist_scan(db, summary, scan_result, scan_mode=scan_mode, localhost_protocol=localhost_protocol)
    return summary, scan_result


def _latest_or_safe_scan(db: AuditDatabase, *, requested_scan: ScanResult | None) -> ScanResult:
    if requested_scan is not None:
        return requested_scan
    latest = db.latest_scan_result()
    if latest is not None:
        return latest
    return _run_scan(db, aggressive=False)[1]


def _system_health(db: AuditDatabase) -> dict:
    config = AuditConfig(logs_dir=db.logs_dir)
    engine = OperationalHealthEngine(
        db,
        user_launch_agent=LaunchAgentManager(db.path),
        system_launch_agent=LaunchAgentManager(default_monitor_db_path("system"), scope="system"),
        notification_manager=NotificationManager(db),
        system_readiness=SystemMonitorReadiness(default_monitor_db_path("system")),
        cve_radar_engine=CveRadarEngine(db, config),
    )
    return engine.build_report().to_dict()


def _release_readiness(db: AuditDatabase, *, run_expensive: bool = False, pytest_python: str | None = None) -> dict:
    return ReleaseReadinessEngine(db, pytest_python=pytest_python).build_report(run_expensive=run_expensive).to_dict()


def _verify_event_flow(monitor_db_path: Path, *, timeout_seconds: int) -> dict:
    readiness = SystemMonitorReadiness(monitor_db_path)
    result = readiness.verify_event_flow(timeout_seconds=timeout_seconds)
    payload = result.to_dict()
    db = AuditDatabase(monitor_db_path)
    db.set_background_monitor_state("deployment_event_flow_last_report_json", json.dumps(payload, sort_keys=True))
    return payload


def _verify_visible_alert(db: AuditDatabase, *, event_type: str = "lid_opened") -> dict:
    requested_event_type = str(event_type or "").strip()
    canonical_type = canonical_event_type(requested_event_type)
    mandatory_types = {canonical_event_type(item) for item in MANDATORY_VISIBLE_ALERT_EVENT_TYPES}
    if canonical_type not in mandatory_types:
        payload = {
            "generated_at": utc_now_iso(),
            "event_id": "",
            "event_type": canonical_type,
            "requested_event_type": requested_event_type,
            "db_path": str(db.path),
            "stored_success": False,
            "policy": {},
            "visible_alert_delivered": False,
            "trace": {},
            "deliveries": [],
            "stages": [
                {
                    "check_id": "mandatory_visible_event_type",
                    "status": "FAIL",
                    "observed": canonical_type,
                    "details": "Visible alert release verification requires a mandatory visible event type.",
                }
            ],
        }
        db.set_background_monitor_state("visible_alert_verification_last_report_json", json.dumps(payload, sort_keys=True))
        return payload
    event_id = f"visible-alert-{uuid4().hex[:12]}"
    event = BackgroundMonitorEvent(
        event_id=event_id,
        timestamp=utc_now_iso(),
        event_type=canonical_type,
        severity="high",
        source="cli_visible_alert_verification",
        evidence=f"Synthetic visible alert verification for {canonical_type}.",
        confidence="high",
        recommendation="No action required. This is an operational readiness verification event.",
        simulated=True,
        rule_id=f"msaa.verify_visible_alert.{canonical_type}",
        trigger_source="cli_visible_alert_verification",
    )
    stored = db.record_monitor_event(event, dedupe_window_seconds=0)
    trace_id = f"trace-{event.event_id}"
    db.record_event_alert_trace(
        EventAlertTrace(
            trace_id=trace_id,
            event_id=event.event_id,
            event_type=event.event_type,
            original_event_type=requested_event_type,
            normalized_event_type=event.event_type,
            detector_source="cli_visible_alert_verification",
            created_at=event.timestamp,
            stored_db_path=str(db.path),
            stored_success=bool(stored),
            notifier_db_path=str(db.path),
            notifier_seen=True,
            notifier_seen_at=utc_now_iso(),
            notification_policy_checked=False,
            alert_queue_enqueued=bool(stored),
            severity_before_policy=event.severity,
            severity_after_policy=event.severity,
        )
    )
    notifier = NotificationManager(db)
    decision = notifier.evaluate_notification_decision(event, force=True)
    delivered = notifier.show_visible_security_alert(event, reason="cli_visible_alert_verification", force=True)
    db.update_monitor_event_notification(
        event.event_id,
        notification_sent=bool(delivered),
        notification_error="" if delivered else "visible alert overlay delivery failed",
        notification_returncode=0 if delivered else 1,
        notification_decision="sent" if delivered else "overlay_failed",
        notification_reason="cli_visible_alert_verification",
        cooldown_remaining_seconds=0,
        popup_allowed=True,
        visible_alert_shown=bool(delivered),
        alert_style=getattr(event, "alert_style", ""),
        cooldown_suppressed=False,
        last_suppression_reason="",
    )
    trace = db.get_event_alert_trace(event.event_id)
    deliveries = [item.to_dict() for item in db.latest_alert_delivery_records(limit=25) if item.event_id == event.event_id]
    payload = {
        "generated_at": utc_now_iso(),
        "event_id": event.event_id,
        "event_type": event.event_type,
        "db_path": str(db.path),
        "stored_success": bool(stored),
        "policy": decision,
        "visible_alert_delivered": bool(delivered),
        "trace": trace.to_dict() if trace else {},
        "deliveries": deliveries,
        "stages": [
            {"check_id": "canonical_event_created", "status": "PASS", "observed": event.event_type},
            {"check_id": "sqlite_store", "status": "PASS" if stored else "FAIL", "observed": str(db.path)},
            {"check_id": "notifier_policy_checked", "status": "PASS" if decision.get("decision") else "FAIL", "observed": str(decision.get("decision", ""))},
            {"check_id": "overlay_dispatch", "status": "PASS" if delivered else "FAIL", "observed": str((trace.to_dict() if trace else {}).get("overlay_dispatch_result", ""))},
            {"check_id": "visible_alert_delivery", "status": "PASS" if delivered else "FAIL", "observed": str((trace.to_dict() if trace else {}).get("visible_alert_id", ""))},
        ],
    }
    db.set_background_monitor_state("visible_alert_verification_last_report_json", json.dumps(payload, sort_keys=True))
    return payload


def _run_json_subprocess(command: list[str], *, timeout: int = 60, max_chars: int | None = 4000) -> dict:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    stdout = result.stdout if max_chars is None else result.stdout[-max_chars:]
    stderr = result.stderr if max_chars is None else result.stderr[-max_chars:]
    combined_output = f"{stdout}{stderr}"
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "combined_output": combined_output if max_chars is None else combined_output[-max_chars:],
    }


def _newest_wheel(repo_root: Path) -> Path | None:
    wheels = sorted((repo_root / "dist").glob("*.whl"), key=lambda path: path.stat().st_mtime, reverse=True)
    return wheels[0] if wheels else None


def _verify_clean_install(db: AuditDatabase, *, python_executable: Path, wheel_path: Path | None = None) -> dict:
    repo_root = Path(__file__).resolve().parent.parent
    wheel = wheel_path or _newest_wheel(repo_root)
    stages: list[dict[str, object]] = []
    payload: dict[str, object] = {
        "generated_at": utc_now_iso(),
        "python": str(python_executable),
        "wheel": str(wheel or ""),
        "stages": stages,
    }

    version_probe = _run_json_subprocess(
        [
            str(python_executable),
            "-c",
            "import json,sys; print(json.dumps({'version': sys.version, 'major': sys.version_info[0], 'minor': sys.version_info[1], 'micro': sys.version_info[2]}))",
        ],
        timeout=20,
    )
    version_ok = version_probe["returncode"] == 0
    version_payload = {}
    if version_ok:
        try:
            version_payload = json.loads(str(version_probe.get("stdout", "")).strip())
        except json.JSONDecodeError:
            version_ok = False
    python_ok = version_ok and (int(version_payload.get("major", 0)), int(version_payload.get("minor", 0))) >= (3, 10)
    stages.append(
        {
            "check_id": "python_version",
            "status": "PASS" if python_ok else "FAIL",
            "observed": version_payload.get("version", version_probe.get("stderr", "")),
            "details": "Clean install verification requires Python 3.10 or newer.",
        }
    )
    wheel_ok = bool(wheel and wheel.exists())
    stages.append({"check_id": "wheel_exists", "status": "PASS" if wheel_ok else "FAIL", "observed": str(wheel or ""), "details": "Build dist/*.whl before clean install verification."})
    if not python_ok or not wheel_ok:
        db.set_background_monitor_state("clean_install_last_report_json", json.dumps(payload, sort_keys=True))
        return payload

    temp_root = Path(tempfile.mkdtemp(prefix="msaa-clean-install-"))
    venv_path = temp_root / "venv"
    try:
        venv_result = _run_json_subprocess([str(python_executable), "-m", "venv", str(venv_path)], timeout=120)
        stages.append({"check_id": "venv_create", "status": "PASS" if venv_result["returncode"] == 0 else "FAIL", "observed": venv_result.get("combined_output") or str(venv_path)})
        venv_python = venv_path / "bin" / "python"
        if venv_result["returncode"] == 0:
            install_result = _run_json_subprocess([str(venv_python), "-m", "pip", "install", str(wheel)], timeout=240)
            stages.append({"check_id": "wheel_install", "status": "PASS" if install_result["returncode"] == 0 else "FAIL", "observed": install_result.get("combined_output", "")})
        else:
            install_result = {"returncode": 1}
        if install_result["returncode"] == 0:
            import_result = _run_json_subprocess([str(venv_python), "-c", "import mac_audit_agent, mac_audit_agent.cli, mac_audit_agent.reliability; print('imports ok')"], timeout=60)
            stages.append({"check_id": "import_sweep", "status": "PASS" if import_result["returncode"] == 0 else "FAIL", "observed": import_result.get("combined_output", "")})
            resource_result = _run_json_subprocess([str(venv_python), "-c", "from mac_audit_agent.assets import get_asset_path; print(get_asset_path('logo.png').exists()); print(get_asset_path('app_icon.icns').exists())"], timeout=60)
            stages.append({"check_id": "resource_check", "status": "PASS" if resource_result["returncode"] == 0 and 'True\nTrue' in str(resource_result["stdout"]) else "FAIL", "observed": resource_result.get("combined_output", "")})
            help_result = _run_json_subprocess([str(venv_path / "bin" / "macos-security-audit-agent"), "--help"], timeout=60)
            stages.append({"check_id": "console_help", "status": "PASS" if help_result["returncode"] == 0 else "FAIL", "observed": help_result.get("combined_output", "")})
            readiness_result = _run_json_subprocess([str(venv_path / "bin" / "macos-security-audit-agent"), "--db", str(temp_root / "audit.sqlite"), "--release-readiness", "--no-gui"], timeout=120, max_chars=None)
            readiness_json_ok = False
            readiness_status = ""
            if readiness_result["returncode"] == 0:
                try:
                    parsed = json.loads(str(readiness_result["stdout"]))
                    readiness_status = str(parsed.get("status", ""))
                    readiness_json_ok = (
                        isinstance(parsed.get("ReleaseReadinessScore"), int)
                        and isinstance(parsed.get("checks"), list)
                        and readiness_status in {"ready", "needs work", "blocked"}
                    )
                except json.JSONDecodeError:
                    readiness_json_ok = False
            stages.append(
                {
                    "check_id": "release_readiness_cli",
                    "status": "PASS" if readiness_json_ok else "FAIL",
                    "observed": readiness_result.get("combined_output", ""),
                    "details": f"installed readiness status={readiness_status or 'unavailable'}",
                }
            )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    db.set_background_monitor_state("clean_install_last_report_json", json.dumps(payload, sort_keys=True))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    action_requested = any([args.safe_scan, args.aggressive_scan, args.report, args.json_report, args.system_health, args.release_readiness, args.release_readiness_expensive, args.verify_event_flow, args.verify_visible_alert, args.verify_clean_install])
    if not action_requested:
        if args.no_gui:
            parser.print_help()
            return 0
        return gui_main()

    db = AuditDatabase(args.db, _logs_dir_for_db(args.db))
    scan_result: ScanResult | None = None
    exit_code = 0
    if args.safe_scan or args.aggressive_scan:
        summary, scan_result = _run_scan(db, aggressive=bool(args.aggressive_scan))
        print(
            json.dumps(
                {
                    "scan_id": summary.scan_id,
                    "findings_count": summary.findings_count,
                    "security_score": summary.security_score,
                    "score_label": summary.score_label,
                    "database": str(args.db),
                },
                indent=2,
            )
        )
    if args.report:
        report_scan = _latest_or_safe_scan(db, requested_scan=scan_result)
        path = export_scan_result_html(report_scan, args.report)
        print(f"HTML report written: {path}")
    if args.json_report:
        report_scan = _latest_or_safe_scan(db, requested_scan=scan_result)
        path = export_scan_result_json(report_scan, args.json_report)
        print(f"JSON report written: {path}")
    if args.system_health:
        print(json.dumps(_system_health(db), indent=2, sort_keys=True))
    if args.verify_event_flow:
        payload = _verify_event_flow(args.monitor_db, timeout_seconds=args.event_flow_timeout)
        print(json.dumps(payload, indent=2, sort_keys=True))
        if any(str(stage.get("status", "")).upper() == "FAIL" for stage in payload.get("stages", [])):
            exit_code = max(exit_code, 2)
    if args.verify_visible_alert:
        payload = _verify_visible_alert(db, event_type=str(args.visible_alert_event_type))
        print(json.dumps(payload, indent=2, sort_keys=True))
        if any(str(stage.get("status", "")).upper() == "FAIL" for stage in payload.get("stages", [])):
            exit_code = max(exit_code, 2)
    if args.verify_clean_install:
        payload = _verify_clean_install(db, python_executable=args.clean_install_python, wheel_path=args.clean_install_wheel)
        print(json.dumps(payload, indent=2, sort_keys=True))
        if any(str(stage.get("status", "")).upper() == "FAIL" for stage in payload.get("stages", [])):
            exit_code = max(exit_code, 2)
    if args.release_readiness or args.release_readiness_expensive:
        print(json.dumps(_release_readiness(db, run_expensive=bool(args.release_readiness_expensive), pytest_python=args.release_pytest_python), indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

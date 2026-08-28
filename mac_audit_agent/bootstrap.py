"""Dependency-free command boundary for source, installed, and frozen modes."""

import sys
import json
import hashlib
import tempfile
from pathlib import Path

from mac_audit_agent.runtime.startup import display_frozen_failure, error_code_from_message, gui_dependency_failure, is_root_user, python_supported, report_exception, requested_mode, root_gui_message, unsupported_python_message, write_failure_log


def _emit_failure(message):
    print(message, file=sys.stderr)
    display_frozen_failure(message)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    debug = "--debug" in argv
    if debug:
        argv.remove("--debug")
    mode = requested_mode(argv)
    if "--launchd" in argv and ("doctor" in argv or "--doctor" in argv):
        from mac_audit_agent.platform.macos.launchd_service import LaunchdServiceManager
        report = LaunchdServiceManager().detect()
        if "--json" in argv:
            print(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            print("MSAA launchd monitor doctor")
            for key in ("label", "console_user", "console_uid", "effective_uid", "expected_domain", "loaded_gui", "loaded_system", "state", "error_code", "recommended_bootout_target", "recommended_bootstrap_target"):
                print(f"{key.replace('_', ' ').title()}: {report.get(key, '')}")
            print("Detected plists:")
            for path in report.get("detected_plists", []): print(f"- {path}")
        return 0 if not report.get("error_code") else 1
    if mode == "gui" and is_root_user():
        message = root_gui_message()
        write_failure_log("PRIV001", message)
        _emit_failure(message)
        return 2
    if "--doctor" in argv and sys.version_info[:2] >= (3, 9):
        try:
            from mac_audit_agent.runtime.doctor import doctor_main

            return doctor_main(as_json="--json" in argv, topology_only="--topology" in argv)
        except Exception as exc:
            _, message = report_exception(exc, debug=debug)
            _emit_failure(message)
            return 2
    if not python_supported():
        message = unsupported_python_message()
        write_failure_log("PY001", message)
        _emit_failure(message)
        return 2
    if "--help-topic" in argv:
        try:
            index = argv.index("--help-topic")
            identifier = argv[index + 1]
            from mac_audit_agent.help.diagnostic_registry import resolve_help_topic
            result = resolve_help_topic(identifier)
            if result.topic is None:
                print(json.dumps(result.failure_event(), sort_keys=True))
                return 2
            payload = {"topic_id":result.topic.topic_id, "title":result.topic.title,
                "resource":result.topic.resource, "resource_sha256":hashlib.sha256(result.topic.resource_content.encode()).hexdigest(),
                "renderable":bool(result.topic.resource_content.strip())}
            print(json.dumps(payload, sort_keys=True))
            return 0
        except (IndexError, ValueError, OSError) as exc:
            print(json.dumps({"event":"help_topic_resolution_failed", "reason":type(exc).__name__}), file=sys.stderr)
            return 2
    if mode == "gui":
        from mac_audit_agent.runtime.gui_preflight import evaluate_gui_preflight
        preflight = evaluate_gui_preflight()
        if not preflight.allowed:
            write_failure_log(preflight.failure_code, preflight.message)
            print(preflight.message, file=sys.stderr)
            return 2
    if "--packaged-gui-smoke" in argv:
        try:
            from mac_audit_agent.runtime.qapplication_guard import assert_qapplication_allowed
            assert_qapplication_allowed(preflight)
            from PySide6.QtWidgets import QApplication
            from mac_audit_agent.ui.main_window import MainWindow
            app = QApplication.instance() or QApplication([])
            with tempfile.TemporaryDirectory(prefix="msaa-gui-smoke-") as root:
                window = MainWindow(Path(root) / "smoke.sqlite")
                window.show()
                app.processEvents()
                window.open_help_topic("AR022")
                app.processEvents()
                result = {"main_window_visible":window.isVisible(), "qt_platform_loaded":bool(app.platformName()),
                    "help_topic":window.help_viewer.current_topic_id, "help_rendered":"Detected Conditions" in window.help_viewer.content_view.toPlainText()}
                window.help_viewer.close()
                window.close()
                app.processEvents()
            print(json.dumps(result, sort_keys=True))
            return 0 if all(result.values()) else 2
        except Exception as exc:
            print(json.dumps({"event":"packaged_gui_smoke_failed", "reason":type(exc).__name__, "message":str(exc)}), file=sys.stderr)
            return 2
    if "--user-notifier-service" in argv:
        from mac_audit_agent.user_notifier import main as notifier_main

        return notifier_main(["--run"])
    if "--service-watchdog" in argv:
        from mac_audit_agent.service_watchdog import main as watchdog_main

        remaining = [value for value in argv if value != "--service-watchdog"]
        return watchdog_main(["run-once", *remaining])
    if "--sensor-health" in argv:
        from mac_audit_agent.sensor_health_service import main as sensor_health_main

        remaining = [value for value in argv if value != "--sensor-health"]
        return sensor_health_main(["run-once", *remaining])
    if "--system-monitor-service" in argv or "--user-monitor-service" in argv:
        from mac_audit_agent.monitor import main as monitor_main

        role = "system-daemon" if "--system-monitor-service" in argv else "user-notifier"
        return monitor_main(["--run", "--mode", role])
    if not argv:
        message = gui_dependency_failure()
        if message:
            write_failure_log(error_code_from_message(message), message)
            _emit_failure(message)
            return 2
    try:
        from mac_audit_agent.cli import main as cli_main

        return cli_main(argv)
    except Exception as exc:
        _, message = report_exception(exc, debug=debug)
        _emit_failure(message)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

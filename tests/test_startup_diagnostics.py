from __future__ import annotations

import json
import subprocess
from pathlib import Path

from mac_audit_agent import bootstrap
from mac_audit_agent.runtime import doctor, startup


def test_unsupported_python_message_is_actionable(monkeypatch) -> None:
    monkeypatch.setattr(startup.sys, "version_info", (3, 9, 18))

    message = startup.unsupported_python_message()

    assert "PY001" in message
    assert "Python 3.9.18" in message
    assert startup.os.path.abspath(startup.sys.executable) in message
    assert "-m venv .venv" in message


def test_bootstrap_stops_before_application_import_on_unsupported_python(monkeypatch, capsys) -> None:
    monkeypatch.setattr(bootstrap, "python_supported", lambda: False)
    monkeypatch.setattr(bootstrap, "unsupported_python_message", lambda: "friendly PY001 message")
    monkeypatch.setattr(bootstrap, "write_failure_log", lambda *args, **kwargs: Path("test.log"))

    assert bootstrap.main(["--help"]) == 2
    assert "friendly PY001 message" in capsys.readouterr().err


def test_missing_gui_dependency_uses_detected_interpreter(monkeypatch) -> None:
    monkeypatch.setattr(startup.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(startup.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(startup.importlib.metadata, "version", lambda name: (_ for _ in ()).throw(startup.importlib.metadata.PackageNotFoundError))

    message = startup.gui_dependency_failure()

    assert message is not None
    assert "DEP314001" in message
    assert startup.os.path.abspath(startup.sys.executable) in message
    assert "-m pip" in message


def test_native_dependency_import_failure_is_distinct(monkeypatch) -> None:
    monkeypatch.setattr(startup, "is_frozen", lambda: False)
    exc = ImportError("dlopen failed: wrong architecture")
    exc.name = "PySide6.QtCore"

    code, problem, component, _ = startup.classify_import_failure(exc)

    assert code == "SYS001"
    assert "native" in problem.lower()
    assert component["distribution"] == "PySide6"


def test_installed_dependency_import_failure_is_dep003(monkeypatch) -> None:
    monkeypatch.setattr(startup, "is_frozen", lambda: False)
    exc = ImportError("package initialization failed")
    exc.name = "docx"

    code, _, component, _ = startup.classify_import_failure(exc)

    assert code == "DEP003"
    assert component["distribution"] == "python-docx"
    assert component["installed"] == "installed but import failed"


def test_incompatible_gui_dependency_reports_versions(monkeypatch) -> None:
    monkeypatch.setattr(startup.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(startup.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(startup.importlib.metadata, "version", lambda name: "6.5.0")

    message = startup.gui_dependency_failure()

    assert message is not None
    assert "DEP314002" in message
    assert "6.5.0" in message
    assert ">=6.10.1" in message


def test_bootstrap_logs_specific_gui_error_code(monkeypatch) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(bootstrap, "python_supported", lambda: True)
    monkeypatch.setattr(bootstrap, "gui_dependency_failure", lambda: "- Error code: DEP002")
    monkeypatch.setattr(bootstrap, "write_failure_log", lambda code, message: recorded.append(code))
    monkeypatch.setattr(bootstrap, "_emit_failure", lambda message: None)

    assert bootstrap.main([]) == 2
    assert recorded == ["DEP002"]


def test_frozen_dependency_failure_does_not_recommend_pip(monkeypatch) -> None:
    monkeypatch.setattr(startup, "is_frozen", lambda: True)

    code, _, _, fixes = startup.classify_import_failure(ModuleNotFoundError("missing", name="PySide6"))

    assert code == "PKG001"
    assert all("pip" not in step for step in fixes)


def test_frozen_automation_never_opens_startup_dialog(monkeypatch) -> None:
    monkeypatch.setattr(startup, "is_frozen", lambda: True)
    monkeypatch.setattr(startup.sys, "argv", ["Mac Audit Agent", "--smoke-test", "--no-dialogs", "--json"])

    assert startup.display_frozen_failure("sentinel") is False
    assert "PySide6" not in startup.sys.modules


def test_doctor_json_is_machine_readable_and_redacts_home(monkeypatch, capsys) -> None:
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    assert doctor.doctor_main(as_json=True) in {0, 2}
    payload = json.loads(capsys.readouterr().out)

    assert payload["result"] in {"PASS", "DEGRADED", "FAIL"}
    assert payload["python"]["supported_range"] == "3.10-3.14"
    assert str(Path.home()) not in json.dumps(payload)
    assert payload["network"]["checked"] is False


def test_supported_python_range_boundaries(monkeypatch) -> None:
    monkeypatch.setattr(startup.sys, "version_info", (3, 10, 0))
    assert startup.python_supported() is True
    monkeypatch.setattr(startup.sys, "version_info", (3, 13, 99))
    assert startup.python_supported() is True
    monkeypatch.setattr(startup.sys, "version_info", (3, 14, 0))
    assert startup.python_supported() is True
    monkeypatch.setattr(startup.sys, "version_info", (3, 15, 0))
    assert startup.python_supported() is False


def test_incompatible_optional_dependency_is_degraded(monkeypatch) -> None:
    monkeypatch.setattr(doctor.importlib.metadata, "version", lambda name: "1.0")
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: object())

    status = doctor._dependency_status("openpyxl", doctor.DEPENDENCIES["openpyxl"])

    assert status["compatible"] is False
    assert status["status"] == "DEGRADED"


def test_unexpected_failure_writes_traceback_log(tmp_path, monkeypatch) -> None:
    log = tmp_path / "startup.log"
    monkeypatch.setattr(startup, "diagnostic_log_path", lambda: log)

    try:
        raise RuntimeError("diagnostic sentinel")
    except RuntimeError as exc:
        code, message = startup.report_exception(exc)

    assert code == "APP999"
    assert "diagnostic sentinel" in log.read_text(encoding="utf-8")
    assert "Traceback" not in message


def test_debug_failure_includes_traceback(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(startup, "diagnostic_log_path", lambda: tmp_path / "startup.log")

    try:
        raise ValueError("debug sentinel")
    except ValueError as exc:
        _, message = startup.report_exception(exc, debug=True)

    assert "Debug traceback:" in message
    assert "ValueError: debug sentinel" in message


def test_missing_resource_is_reported(monkeypatch) -> None:
    from mac_audit_agent import assets

    monkeypatch.setattr(assets, "get_asset_path", lambda name: Path("/definitely/missing") / name)
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    report = doctor.build_doctor_report()

    assert report["result"] == "FAIL"
    assert all(item["status"] == "FAIL" for item in report["resources"])


def test_frozen_resource_root_uses_meipass(tmp_path, monkeypatch) -> None:
    from mac_audit_agent import assets

    bundled = tmp_path / "bundle" / "mac_audit_agent" / "assets"
    bundled.mkdir(parents=True)
    (bundled / "logo.png").write_bytes(b"png")
    monkeypatch.setattr(assets.sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)

    assert assets.get_asset_path("logo.png") == bundled / "logo.png"


def test_missing_external_tool_is_degraded(monkeypatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    report = doctor.build_doctor_report()

    assert all(item["status"] == "DEGRADED" for item in report["external_tools"])


def test_external_tool_timeout_is_degraded(monkeypatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/example")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(args[0], 3)))

    item = doctor._tool_status("example")

    assert item["status"] == "DEGRADED"
    assert item["error_code"] == "SYS002"


def test_unwritable_locations_fail_diagnostics(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_writable", lambda path: False)

    report = doctor.build_doctor_report()

    assert report["result"] == "FAIL"
    assert all(item["status"] == "FAIL" for item in report["locations"])


def test_secret_environment_value_is_never_reported(monkeypatch) -> None:
    monkeypatch.setenv("MSAA_RELEASE_SIGNING_KEY", "top-secret-value")
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    report = doctor.build_doctor_report()
    serialized = json.dumps(report)

    assert "top-secret-value" not in serialized
    assert report["redacted_environment"]["MSAA_RELEASE_SIGNING_KEY"] == "<redacted>"


def test_mismatched_virtual_environment_is_configuration_failure(monkeypatch) -> None:
    monkeypatch.setenv("VIRTUAL_ENV", "/different/environment")
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    report = doctor.build_doctor_report()

    assert report["python"]["virtual_environment"]["consistent"] is False
    assert report["python"]["virtual_environment"]["error_code"] == "CFG001"
    assert report["result"] == "FAIL"


def test_missing_pip_is_reported_without_installing(monkeypatch) -> None:
    real_find_spec = doctor.importlib.util.find_spec
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda name: None if name == "pip" else real_find_spec(name))
    monkeypatch.setattr(doctor, "_writable", lambda path: True)

    report = doctor.build_doctor_report()

    assert report["pip"]["available"] is False
    assert report["pip"]["status"] == "DEGRADED"

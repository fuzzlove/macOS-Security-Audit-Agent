from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from mac_audit_agent.runtime.startup import MAX_PYTHON, MIN_PYTHON, is_frozen, mode_name, quote_command

DEPENDENCIES = {
    "PySide6": {"module": "PySide6", "requirement": ">=6.10.1", "extra": "gui", "required": False, "capability": "GUI"},
    "openpyxl": {"module": "openpyxl", "requirement": ">=3.1", "extra": "office", "required": False, "capability": "Excel export"},
    "python-docx": {"module": "docx", "requirement": ">=1.1", "extra": "office", "required": False, "capability": "Word export"},
}
EXTERNAL_TOOLS = ("git", "openssl", "nmap", "ykman", "pkcs11-tool")
TOOL_VERSION_ARGS = {"openssl": ("version",)}
REQUIRED_RESOURCES = ("logo.png", "app_icon.icns", "security_quotes.json")
SECRET_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL")


def _redact(value: str) -> str:
    home = str(Path.home())
    root = str(Path(__file__).resolve().parents[2])
    output = value.replace(str(Path.home() / "Library" / "Application Support" / "MacAuditAgent"), "<APP_SUPPORT>")
    output = output.replace("/Library/Application Support/MacAuditAgent", "<SYSTEM_APP_SUPPORT>")
    if root:
        output = output.replace(root, "<PROJECT_ROOT>")
    return output.replace(home, "<HOME>") if home and home != "/" else output


def _dependency_status(distribution: str, spec: dict[str, Any], *, doctor_only: bool = False) -> dict[str, Any]:
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        version = "not installed"
    module_available = importlib.util.find_spec(str(spec["module"])) is not None
    compatible = version == "not installed" or _version_at_least(version, str(spec["requirement"]).removeprefix(">="))
    if doctor_only:
        status = "INFO" if module_available and compatible else "OPTIONAL_MISSING"
    else:
        status = "PASS" if module_available and compatible else ("FAIL" if spec["required"] else "OPTIONAL_MISSING")
    error_code = "" if status == "PASS" else ("DEP001" if version == "not installed" else "DEP002")
    target = ".[{}]".format(spec["extra"]) if mode_name() == "source checkout" else "macos-security-audit-agent[{}]".format(spec["extra"])
    install_command = "Reinstall or replace this incomplete application bundle." if is_frozen() else quote_command([sys.executable, "-m", "pip", "install", "--upgrade", target])
    if doctor_only:
        install_command = 'Create a Python 3.12/3.13 project virtual environment, then run: python -m pip install -e ".[{}]"'.format(spec["extra"])
    return {"distribution": distribution, **spec, "installed_version": version, "module_available": module_available, "compatible": compatible, "status": status, "error_code": error_code if status not in {"INFO", "OPTIONAL_MISSING"} else "", "install_command": install_command, "current_mode_affected": not doctor_only, "install_into_current_interpreter": not doctor_only, "runtime_decision": "GUI blocked because Python 3.9 is deprecated doctor-only." if doctor_only and distribution == "PySide6" else "Optional capability is not used by doctor-only mode." if doctor_only else "Capability follows dependency availability."}


def _version_at_least(observed: str, minimum: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        output: list[int] = []
        for part in value.split("."):
            digits = "".join(character for character in part if character.isdigit())
            if not digits:
                break
            output.append(int(digits))
        return tuple(output)

    return parts(observed) >= parts(minimum)


def _writable(path: Path) -> bool:
    existing = path
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    return os.access(existing, os.W_OK)


def _tool_status(name: str, *, doctor_only: bool = False) -> dict[str, Any]:
    capabilities = {"nmap": "Enhanced network discovery", "pkcs11-tool": "Legacy PKCS#11/YubiKey signing", "ykman": "YubiKey management", "git": "Source/release workflows", "openssl": "Signature verification fallback"}
    path = shutil.which(name)
    if not path:
        status = "INFO" if name == "pkcs11-tool" else "OPTIONAL_MISSING"
        return {"name": name, "path": "not found", "version": "unavailable", "required": False, "status": status, "error_code": "", "capability": capabilities.get(name, name), "current_mode_affected": False, "fallback": "Basic local network visibility remains available through macOS system tools." if name == "nmap" else "Ignored unless PKCS#11 signing is explicitly enabled." if name == "pkcs11-tool" else "Optional tool is not required by the selected doctor mode.", "trust_policy": "developer-machine signing" if name == "pkcs11-tool" else "not applicable"}
    try:
        result = subprocess.run([path, *TOOL_VERSION_ARGS.get(name, ("--version",))], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"name": name, "path": _redact(path), "version": "unavailable", "required": False, "status": "OPTIONAL_MISSING", "error_code": "", "details": "%s: %s" % (type(exc).__name__, exc), "capability": capabilities.get(name, name), "current_mode_affected": False}
    output = (result.stdout or result.stderr or "").strip().splitlines()
    version = output[0][:200] if output else "not reported"
    status = "PASS" if result.returncode == 0 and output else "OPTIONAL_MISSING"
    if doctor_only and status == "PASS": status = "INFO"
    return {"name": name, "path": _redact(path), "version": version, "required": False, "status": status, "error_code": "" if status in {"PASS", "INFO"} else "SYS002", "returncode": result.returncode, "capability": capabilities.get(name, name), "current_mode_affected": False if doctor_only else status != "PASS"}


def _virtual_environment_status() -> dict[str, Any]:
    active = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    declared = os.environ.get("VIRTUAL_ENV", "")
    prefix = os.path.abspath(sys.prefix)
    consistent = not declared or os.path.normcase(os.path.abspath(declared)) == os.path.normcase(prefix)
    return {
        "active": active,
        "prefix": _redact(prefix),
        "declared_by_environment": _redact(declared),
        "consistent": consistent,
        "status": "PASS" if consistent else "FAIL",
        "error_code": "" if consistent else "CFG001",
        "details": "VIRTUAL_ENV matches sys.prefix." if consistent else "VIRTUAL_ENV points to a different interpreter environment than sys.prefix.",
        "how_to_fix": "Deactivate the stale environment, activate %s, and retry with %s." % (_redact(prefix), _redact(os.path.abspath(sys.executable))) if not consistent else "No action required.",
    }


def build_doctor_report() -> dict[str, Any]:
    from mac_audit_agent.compat.python_features import detect_python_features
    from mac_audit_agent.runtime.python_runtime_gate import evaluate_python_runtime
    from mac_audit_agent.runtime.detector import detect_python_runtime
    from mac_audit_agent.runtime.capabilities import CapabilityRegistry
    from mac_audit_agent.runtime.setup_guidance import build_setup_guidance
    from mac_audit_agent.runtime.gui_preflight import evaluate_gui_preflight
    from mac_audit_agent.platform import detect_architecture, detect_execution_mode, detect_macos_version, detect_python_details, evaluate_platform_capabilities, resolve_platform_paths
    try:
        APP_VERSION = importlib.metadata.version("macos-security-audit-agent")
    except importlib.metadata.PackageNotFoundError:
        APP_VERSION = "source"
    package_root = Path(__file__).resolve().parents[1]
    def get_asset_path(name: str) -> Path:
        return package_root / "assets" / name

    version_ok = MIN_PYTHON <= sys.version_info[:2] <= MAX_PYTHON
    doctor_only = sys.version_info[:2] < (3, 10)
    pip_available = importlib.util.find_spec("pip") is not None
    dependencies = [_dependency_status(name, spec, doctor_only=doctor_only) for name, spec in DEPENDENCIES.items()]
    tools = [_tool_status(name, doctor_only=doctor_only) for name in EXTERNAL_TOOLS]
    resources = [{"name": name, "path": _redact(str(get_asset_path(name))), "available": get_asset_path(name).is_file(), "status": "PASS" if get_asset_path(name).is_file() else "FAIL", "error_code": "" if get_asset_path(name).is_file() else ("PKG001" if is_frozen() else "RES001")} for name in REQUIRED_RESOURCES]
    if sys.platform == "darwin":
        data_dir = Path.home() / "Library" / "Application Support" / "MacAuditAgent"
        cache_dir = Path.home() / "Library" / "Caches" / "MacAuditAgent"
        log_dir = Path.home() / "Library" / "Logs" / "MacAuditAgent"
    elif os.name == "nt":
        data_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "MacAuditAgent"
        cache_dir = data_dir / "Cache"
        log_dir = data_dir / "Logs"
    else:
        data_dir = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "mac-audit-agent"
        cache_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "mac-audit-agent"
        log_dir = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "mac-audit-agent"
    locations = [data_dir, cache_dir, log_dir, Path(tempfile.gettempdir())]
    paths = [{"kind": kind, "path": _redact(str(path)), "writable": _writable(path), "status": ("PASS" if _writable(path) else ("INFO" if doctor_only and kind != "temporary" else "FAIL")), "error_code": "" if _writable(path) or (doctor_only and kind != "temporary") else "FS001", "current_mode_affected": kind == "temporary"} for kind, path in zip(("data", "cache", "log", "temporary"), locations)]
    environment = {key: "<redacted>" for key in os.environ if any(marker in key.upper() for marker in SECRET_MARKERS) and key.startswith("MSAA_")}
    venv = _virtual_environment_status()
    legacy_doctor = doctor_only
    if legacy_doctor:
        topology_payload = {"requested_monitor_mode": "doctor_only", "selected_monitor_mode": "doctor_only", "actual_installed_monitor_mode": "skipped_by_policy", "effective_monitor_mode": "doctor_only", "installed_monitor_services": [], "conflicting_monitor_modes": [], "canonical_event_database": "skipped in Python 3.9 doctor-only mode", "settings_storage_database": "skipped in Python 3.9 doctor-only mode", "notifier_event_database": "skipped in Python 3.9 doctor-only mode", "notifier_receipt_database": "skipped in Python 3.9 doctor-only mode", "acknowledgement_store": "skipped in Python 3.9 doctor-only mode", "alert_trace_database": "skipped in Python 3.9 doctor-only mode", "error_codes": [], "aligned": None, "evaluation_status": "not_evaluated_in_doctor_only_mode"}
    else:
        from mac_audit_agent.runtime.topology import resolve_runtime_topology
        topology_payload = resolve_runtime_topology().to_dict()
    failures = sum(item["status"] == "FAIL" for group in (dependencies, resources, paths) for item in group) + (not version_ok) + (venv["status"] == "FAIL")
    degraded = sum(item["status"] == "DEGRADED" for group in (dependencies, tools) for item in group) + (platform.system() != "Darwin")
    optional_missing = any(item["status"] == "OPTIONAL_MISSING" for group in (dependencies, tools) for item in group)
    overall = "FAIL" if failures else ("DOCTOR_ONLY_OK" if legacy_doctor else ("DEGRADED" if degraded else ("PASS_WITH_LIMITATIONS" if optional_missing else "PASS")))
    gui_gate = evaluate_python_runtime()
    python_features = detect_python_features().to_dict()
    running_as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if legacy_doctor:
        protection = {"status": "skipped_by_policy", "reason": "Python 3.9 is deprecated doctor-only; production protection management requires Python 3.10-3.14."}
        callback_results = []
    else:
        from mac_audit_agent.protection.status import resolve_active_protection_status
        from mac_audit_agent.ui.button_callback_registry import validate_callback_source
        protection = resolve_active_protection_status().to_dict()
        callback_results = [item.to_dict() for item in validate_callback_source(Path(__file__).resolve().parents[2])]
    missing_callbacks = [item for item in callback_results if not item["exists"]]
    callback_failure = next((item for item in missing_callbacks if item["owner"] == "AntiRansomwarePanel"), None)
    runtime_info = detect_python_runtime()
    capabilities = CapabilityRegistry(runtime_info)
    capability_summary = capabilities.summary()
    setup_guidance = build_setup_guidance(runtime_info, capabilities).to_dict()
    architecture_info = detect_architecture()
    platform_capabilities = evaluate_platform_capabilities()
    gui_preflight = evaluate_gui_preflight()
    from mac_audit_agent.runtime.app_paths import RuntimePathError, get_ai_summary_path, get_generated_report_directory
    from mac_audit_agent.secure_io import last_persistence_result, probe_report_directory
    try:
        report_directory = get_generated_report_directory()
        ai_summary_path = get_ai_summary_path()
        report_persistence = probe_report_directory(report_directory)
        previous_write = last_persistence_result()
        report_persistence.update({
            "ai_summary_path": str(ai_summary_path),
            "ai_summary_last_write_succeeded": previous_write.succeeded if previous_write else None,
            "ai_summary_last_error_code": previous_write.error_code if previous_write else None,
        })
    except RuntimePathError as exc:
        report_persistence = {
            "report_directory": "invalid",
            "report_directory_exists": False,
            "report_directory_writable": False,
            "report_directory_owner_uid": None,
            "current_uid": os.geteuid() if hasattr(os, "geteuid") else os.getuid(),
            "report_directory_is_symlink": False,
            "ai_summary_path": "invalid",
            "ai_summary_persistence_available": False,
            "ai_summary_last_write_succeeded": False,
            "ai_summary_last_error_code": exc.code,
        }
    return {
        "application": "macOS Security Audit Agent",
        "application_version": APP_VERSION,
        "result": overall,
        "python": {"version": platform.python_version(), "executable": _redact(os.path.abspath(sys.executable)), "implementation": sys.implementation.name, "abi": __import__("sysconfig").get_config_var("SOABI"), "gil_enabled": getattr(sys, "_is_gil_enabled", lambda: True)(), "runtime_tier": "deprecated_doctor_only" if legacy_doctor else runtime_info.runtime_tier, "runtime_tier_display": "Deprecated doctor-only" if legacy_doctor else runtime_info.runtime_tier, "support_state": "deprecated_doctor_only" if legacy_doctor else ("gui_supported" if gui_preflight.allowed else "headless_only"), "doctor_allowed": True, "headless_doctor_allowed": True, "cli_allowed": not legacy_doctor, "protection_install_allowed": not legacy_doctor, "release_allowed": not legacy_doctor and sys.version_info[:2] <= (3, 13), "recommended_python": "Python 3.12 or Python 3.13 for GUI; Python 3.10-3.14 for supported CLI depending on feature", "supported_range": "deprecated doctor-only 3.9; supported CLI follows command policy; GUI exactly 3.12 or 3.13", "gui_runtime_allowed": gui_preflight.allowed, "gui_runtime_reason": gui_preflight.message, "virtual_environment": venv, "features": python_features},
        "gui_preflight": gui_preflight.to_dict(),
        "pip": {
            "available": pip_available,
            "command": "not applicable to frozen applications" if is_frozen() else _redact('\"%s\" -m pip' % os.path.abspath(sys.executable)),
            "status": "NOT_APPLICABLE" if is_frozen() else ("INFO" if legacy_doctor else ("PASS" if pip_available else "DEGRADED")),
            "error_code": "" if pip_available or is_frozen() else "DEP001",
            "how_to_fix": "Reinstall the application bundle; pip is not used in frozen mode." if is_frozen() else ("Do not install MSAA extras into Apple Command Line Tools Python 3.9; use a Python 3.12/3.13 project virtual environment." if legacy_doctor else ("No action required." if pip_available else "Run: %s" % quote_command([sys.executable, "-m", "ensurepip", "--upgrade"]))),
        },
        "system": {"operating_system": platform.system(), "release": platform.release(), "architecture": platform.machine(), "platform": platform.platform()},
        "application_mode": "frozen" if is_frozen() else "source_or_installed",
        "runtime_topology": _redact_topology(topology_payload),
        "frozen": {"enabled": is_frozen(), "bundle_root": _redact(str(getattr(sys, "_MEIPASS", "")))},
        "dependencies": dependencies,
        "external_tools": tools,
        "resources": resources,
        "locations": paths,
        "report_persistence": report_persistence,
        "configuration": {"source": "built-in defaults and persisted application database", "location": "not applicable: no standalone configuration file", "valid": True, "status": "PASS", "repair": "Database-backed settings are validated by their owning subsystem; no configuration file is silently reset."},
        "platform_support": {"supported": platform.system() == "Darwin", "status": "PASS" if platform.system() == "Darwin" else "DEGRADED", "details": "Security collection and the GUI are supported on macOS; bootstrap, installation, and doctor diagnostics are portable."},
        "redacted_environment": environment,
        "network": {"checked": False, "reason": "No network access is required for startup diagnostics."},
        "active_protection": protection,
        "anti_ransomware_panel_callback_audit": {"status": "FAIL" if missing_callbacks else "PASS", "callbacks": callback_results, "missing": missing_callbacks, "failure": f"AntiRansomwarePanel missing callback: {callback_failure['callback']}" if callback_failure else "", "recommended_fix": "Run tests/test_button_functionality.py and implement or reconnect the callback." if missing_callbacks else "No action required."},
        "button_callback_audit": {"status": "FAIL" if missing_callbacks else "PASS", "missing_count": len(missing_callbacks)},
        "import_boundary": {"status": "PASS", "doctor_imports_gui_frameworks": False},
        "privilege": {"running_as_root": running_as_root, "gui_blocked_as_root": running_as_root, "guidance": "Do not start the MSAA GUI with sudo; use elevation only for headless protection install or repair." if running_as_root else "Run the GUI as this normal user."},
        "recommended_command": "python3.12 -m venv .venv" if legacy_doctor else (_redact(quote_command([sys.executable, "-m", "mac_audit_agent"])) if gui_gate.supported_for_gui and not running_as_root else _redact(quote_command([sys.executable, "-m", "mac_audit_agent", "--doctor"]))),
        "protection_install_command": _redact(quote_command(["sudo", "python3.12" if legacy_doctor else sys.executable, "-m", "mac_audit_agent.protection", "install", "--mode", "protected", "--with-system-daemon", "--with-user-notifier", "--apply-current-settings", "--verify", "--verbose"])),
        "runtime_detection": runtime_info.to_dict(),
        "runtime_support_tier": runtime_info.runtime_tier,
        "capabilities": capability_summary,
        "missing_optional_dependencies": sorted({name for item in capability_summary.values() if item["status"] != "available" for name in [*item["optional_modules"], *item["external_commands"]] if name}),
        "setup_guidance": setup_guidance,
        "universal_platform": {"architecture": architecture_info.to_dict(), "macos": detect_macos_version().to_dict(), "python": detect_python_details().to_dict(), "execution_mode": detect_execution_mode().to_dict(), "paths": resolve_platform_paths().to_dict()},
        "platform_capabilities": {key: value.to_dict() for key, value in platform_capabilities.items()},
        "recommended_next_steps": (["python3.12 -m venv .venv", ". .venv/bin/activate", "python -m pip install -U pip", 'python -m pip install -e ".[gui,office]"', "python3.12 launcher.py", "python3.12 -m mac_audit_agent.protection doctor --json", _redact(quote_command(["sudo", "python3.12", "-m", "mac_audit_agent.protection", "install", "--mode", "protected", "--with-system-daemon", "--with-user-notifier", "--apply-current-settings", "--verify", "--verbose"])), _redact(quote_command([sys.executable, "-m", "mac_audit_agent", "--doctor"]))] if legacy_doctor else []),
        "result_reason": "Doctor completed successfully under deprecated Python 3.9. Full MSAA runtime requires Python 3.10-3.14, with GUI recommended on Python 3.12 or 3.13." if legacy_doctor else "Doctor evaluated the selected runtime and available features.",
    }


def _redact_topology(payload: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, str):
            redacted[key] = _redact(value)
        elif isinstance(value, (list, tuple)):
            redacted[key] = [_redact(str(item)) for item in value]
        else:
            redacted[key] = value
    return redacted


def format_doctor_report(report: dict[str, Any]) -> str:
    lines = ["MSAA environment doctor", "Result: %s" % report["result"], "Reason: %s" % report["result_reason"], "", "Python: %s" % report["python"]["version"], "Executable: %s" % report["python"]["executable"], "Runtime tier: %s" % report["python"]["runtime_tier_display"], "Doctor allowed: %s" % ("Yes" if report["python"]["doctor_allowed"] else "No"), "GUI allowed: %s" % ("Yes" if report["python"]["gui_runtime_allowed"] else "No"), "Protection install allowed: %s" % ("Yes" if report["python"]["protection_install_allowed"] else "No"), "Recommended runtime for full MSAA: Python 3.12 or Python 3.13", "Virtual environment: %s (%s)" % (report["python"]["virtual_environment"]["active"], report["python"]["virtual_environment"]["status"]), "System: %s %s (%s)" % (report["system"]["operating_system"], report["system"]["release"], report["system"]["architecture"]), "Mode: %s" % report["application_mode"]]
    features = report["python"]["features"]
    architecture = report["universal_platform"]["architecture"]
    lines.extend([
        "Running as root: %s" % report["privilege"]["running_as_root"],
        "Native hardware architecture: %s" % architecture["native_hardware"],
        "Process/Python architecture: %s / %s" % (architecture["process"], architecture["python"]),
        "Rosetta translated: %s" % architecture["rosetta_translated"],
        "Universal2 interpreter: %s" % architecture["universal2_interpreter"],
        "",
        "Python features:",
        "- enum.StrEnum native: %s" % features["native_strenum"],
        "- MSAA StrEnum compat: %s" % features["msaa_strenum_compat"],
        "- tomllib native: %s" % features["native_tomllib"],
        "- tomllib available: %s" % features["tomllib_available"],
        "- sqlite3 available: %s" % features["sqlite3_available"],
        "- ssl available: %s" % features["ssl_available"],
        "- venv available: %s" % features["venv_available"],
        "- pip available: %s" % report["pip"]["available"],
        "",
        "Dependencies:",
    ])
    for item in report["dependencies"]:
        lines.append("- [%s%s] %s %s" % (item["status"], " " + item["error_code"] if item["error_code"] else "", item["distribution"], item["installed_version"]))
        lines.append("  Capability affected: %s" % item["capability"])
        lines.append("  Current mode affected: %s" % ("Yes" if item["current_mode_affected"] else "No"))
        lines.append("  Install into this Python: %s" % ("Yes" if item["install_into_current_interpreter"] else "No"))
        lines.append("  Runtime decision: %s" % item["runtime_decision"])
        if item["status"] not in {"PASS", "INFO"}:
            lines.append("  Optional setup: %s" % item["install_command"])
    lines.append("\nInstaller:")
    lines.append("- [%s%s] pip: %s" % (report["pip"]["status"], " " + report["pip"]["error_code"] if report["pip"]["error_code"] else "", report["pip"]["command"]))
    if report["pip"]["error_code"]:
        lines.append("  Fix: %s" % report["pip"]["how_to_fix"])
    if report["python"]["virtual_environment"]["status"] == "FAIL":
        lines.append("- [FAIL CFG001] %s" % report["python"]["virtual_environment"]["details"])
        lines.append("  Fix: %s" % report["python"]["virtual_environment"]["how_to_fix"])
    lines.append("\nResources:")
    for item in report["resources"]:
        lines.append("- [%s%s] %s: %s" % (item["status"], " " + item["error_code"] if item["error_code"] else "", item["name"], item["path"]))
    lines.append("\nWritable locations:")
    for item in report["locations"]:
        lines.append("- [%s%s] %s: %s" % (item["status"], " " + item["error_code"] if item["error_code"] else "", item["kind"], item["path"]))
    lines.append("\nOptional external tools:")
    for item in report["external_tools"]:
        lines.append("- [%s%s] %s: %s (%s)" % (item["status"], " " + item["error_code"] if item["error_code"] else "", item["name"], item["path"], item["version"]))
        lines.append("  Capability affected: %s" % item.get("capability", item["name"]))
        lines.append("  Current mode affected: %s" % ("Yes" if item.get("current_mode_affected") else "No"))
        if item.get("fallback"):
            lines.append("  Fallback: %s" % item["fallback"])
    topology = report["runtime_topology"]
    lines.extend([
        "\nRuntime topology:",
        "- Selected monitor mode: %s" % topology["selected_monitor_mode"],
        "- Installed monitor mode: %s" % topology["actual_installed_monitor_mode"],
        "- Event database: %s" % topology["canonical_event_database"],
        "- Notifier source: %s" % topology["notifier_event_database"],
        "- Receipt database: %s" % topology["notifier_receipt_database"],
        "- Aligned: %s" % ("not evaluated in doctor-only mode" if topology.get("aligned") is None else "%s (%s)" % (topology["aligned"], ", ".join(topology["error_codes"]) or "no topology errors")),
        "",
    ])
    if report["recommended_next_steps"]:
        lines.append("Recommended next steps:")
        for index, command in enumerate(report["recommended_next_steps"], 1):
            lines.append("%d. %s" % (index, command))
    else:
        lines.extend(["Recommended command: %s" % report["recommended_command"], "Protection install (headless elevation): %s" % report["protection_install_command"]])
    return "\n".join(lines)


def doctor_main(as_json: bool = False, topology_only: bool = False) -> int:
    report = build_doctor_report()
    if topology_only:
        topology = report["runtime_topology"]
        payload = {
            "application_version": report["application_version"],
            "expected": topology,
            "configured": {"requested_monitor_mode": topology["requested_monitor_mode"], "settings_database": topology["settings_storage_database"]},
            "installed": {"effective_monitor_mode": topology["effective_monitor_mode"], "installed_monitor_services": topology["installed_monitor_services"], "conflicting_monitor_modes": topology["conflicting_monitor_modes"]},
            "observed": {"notifier_input_source": topology["notifier_event_database"], "receipt_store": topology["notifier_receipt_database"], "error_codes": topology["error_codes"]},
        }
        print(json.dumps(payload, indent=2, sort_keys=True) if as_json else "MSAA runtime topology\n" + json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, indent=2, sort_keys=True) if as_json else format_doctor_report(report))
    return 2 if report["result"] == "FAIL" else 0


__all__ = ["DEPENDENCIES", "build_doctor_report", "doctor_main", "format_doctor_report"]

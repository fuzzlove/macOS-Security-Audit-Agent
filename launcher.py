"""MSAA Stage-0 launcher: standard library only until GUI preflight approval."""

import argparse
import json
import multiprocessing
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _parser():
    parser = argparse.ArgumentParser(description="Start MSAA through its macOS-safe runtime guard.")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON for supported headless commands.")
    parser.add_argument("--topology", action="store_true", help="Limit doctor output to runtime topology.")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--safe-gui-check", action="store_true")
    parser.add_argument("--gui-preflight-json", action="store_true", help="Evaluate static GUI safety without importing Qt.")
    parser.add_argument("--print-runtime", action="store_true")
    parser.add_argument("--debug-startup", action="store_true")
    parser.add_argument("--protection-doctor", action="store_true")
    parser.add_argument("--install-protection", action="store_true")
    parser.add_argument("--assume-install-protection", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--repair-protection", action="store_true")
    parser.add_argument("--verify-protection", action="store_true")
    parser.add_argument("--integrity-status", action="store_true")
    parser.add_argument("--integrity-verify", action="store_true")
    parser.add_argument("--no-auto-python", action="store_true", help="Disable automatic selection of a mode-compatible Python runtime.")
    parser.add_argument("--print-python-selection", action="store_true", help="Print Stage-0 runtime candidates and exit without importing MSAA or Qt.")
    parser.add_argument("--install-protection-services", action="store_true")
    parser.add_argument("--repair-protection-services", action="store_true")
    parser.add_argument("--remove-protection-services", action="store_true")
    parser.add_argument("--restart-protection-services", action="store_true")
    parser.add_argument("--service-status", action="store_true")
    parser.add_argument("--bootstrap-only", action="store_true")
    parser.add_argument("--bootstrap-and-launch", action="store_true")
    parser.add_argument("--target-user")
    parser.add_argument("--developer-mode", action="store_true")
    parser.add_argument("--allow-unsigned-development-runtime", action="store_true")
    parser.add_argument("--pre-uat", action="store_true", help="Expose the development-only Pre-UAT Audit section in the GUI.")
    return parser


def _requested_mode(args):
    if args.doctor or args.headless or args.service_status or args.install_protection_services or args.repair_protection_services or args.remove_protection_services or args.restart_protection_services or args.bootstrap_only:
        return "doctor"
    if args.safe_gui_check or args.gui or not any((args.protection_doctor, args.install_protection, args.assume_install_protection, args.repair_protection, args.verify_protection, args.integrity_status, args.integrity_verify)):
        return "gui"
    if any((args.protection_doctor, args.install_protection, args.assume_install_protection, args.repair_protection, args.verify_protection)):
        return "protection"
    if args.integrity_status or args.integrity_verify:
        return "integrity"
    return "headless"


def _version_allowed(version, mode):
    major_minor = tuple(version[:2])
    if mode == "doctor":
        return major_minor >= (3, 9)
    if mode == "gui":
        return major_minor in {(3, 12), (3, 13)}
    return (3, 10) <= major_minor <= (3, 14)


def _candidate_paths(mode, launcher_path=None):
    root = Path(launcher_path or __file__).resolve().parent
    paths = [root / ".venv/bin/python", root / "venv/bin/python"]
    env_names = ("MSAA_GUI_PYTHON", "MSAA_PYTHON") if mode == "gui" else ("MSAA_PYTHON",)
    paths.extend(Path(value).expanduser() for name in env_names for value in [os.environ.get(name, "").strip()] if value)
    versions = ("3.13", "3.12", "3.11", "3.10") if mode == "gui" else ("3.14", "3.13", "3.12", "3.11", "3.10")
    for version in versions:
        command = shutil.which("python" + version)
        if command:
            paths.append(Path(command))
    for prefix in ("/opt/homebrew/opt", "/usr/local/opt"):
        for version in versions:
            paths.append(Path(prefix) / ("python@" + version) / "bin" / ("python" + version))
    generic = shutil.which("python3")
    if generic:
        paths.append(Path(generic))
    paths.append(Path(sys.executable))
    seen = set()
    output = []
    for path in paths:
        # Preserve virtual-environment interpreter paths. Resolving the
        # bin/python symlink to its Homebrew base interpreter discards the
        # environment's site-packages.
        normalized = os.path.abspath(os.path.expanduser(str(path)))
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


def _probe_python(executable, mode):
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        return {"executable": executable, "accepted": False, "reason": "executable not found"}
    code = (
        "import importlib.metadata as m,importlib.util as u,json,platform,sys;"
        "v=lambda n:(m.version(n) if u.find_spec(n) else 'not installed');"
        "print(json.dumps({'version':list(sys.version_info[:3]),"
        "'implementation':sys.implementation.name,'architecture':platform.machine(),"
        "'pyside':v('PySide6'),'shiboken':v('shiboken6')}))"
    )
    try:
        result = subprocess.run([executable, "-c", code], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"executable": executable, "accepted": False, "reason": "%s: %s" % (type(exc).__name__, exc)}
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        version = tuple(payload["version"])
    except (ValueError, KeyError, IndexError, TypeError):
        return {"executable": executable, "accepted": False, "reason": "runtime probe returned invalid data", "stderr": result.stderr[-500:]}
    reason = "accepted" if result.returncode == 0 and payload.get("implementation") == "cpython" and _version_allowed(version, mode) else "Python %s is not allowed for %s" % (".".join(map(str, version)), mode)
    if reason == "accepted" and mode == "gui":
        pyside = str(payload.get("pyside", "not installed"))
        shiboken = str(payload.get("shiboken", "not installed"))
        if "not installed" in {pyside, shiboken} or pyside.split(".")[:2] != shiboken.split(".")[:2]:
            reason = "GUI dependency pair is missing or inconsistent"
    architecture_matches = not platform.machine() or payload.get("architecture") == platform.machine()
    accepted = reason == "accepted" and architecture_matches
    if not architecture_matches:
        reason = "architecture mismatch: %s" % payload.get("architecture")
    return {"executable": executable, "accepted": accepted, "reason": reason, "version": list(version), "architecture": payload.get("architecture", "")}


def select_python_for_mode(mode, launcher_path=None):
    candidates = [_probe_python(path, mode) for path in _candidate_paths(mode, launcher_path)]
    selected = next((item["executable"] for item in candidates if item["accepted"]), "")
    current = os.path.abspath(sys.executable)
    current_probe = next((item for item in candidates if os.path.abspath(item["executable"]) == current), None)
    current_suitable = bool(current_probe and current_probe["accepted"])
    return {"mode": mode, "current": current, "current_version": list(sys.version_info[:3]), "current_suitable": current_suitable, "selected": selected, "candidates": candidates}


def _setup_guidance(selection, auto_disabled=False):
    current = selection["current"]
    clt = "/Library/Developer/CommandLineTools/" in current
    lines = [
        "Automatic Python selection is disabled; the current interpreter is not suitable for the requested mode." if auto_disabled else "MSAA cannot start the requested mode with the current Python, and no suitable runtime was found.",
        "Current interpreter: %s%s" % (current, " (Apple Command Line Tools bootstrap/doctor only)" if clt else ""),
        "", "Recommended full setup:", "  brew install python@3.13", "  python3.13 -m venv .venv", "  . .venv/bin/activate", "  python -m pip install -U pip", '  python -m pip install -e ".[gui,office]"', "  python launcher.py",
        "", "Doctor-only on the current interpreter:", "  python3 launcher.py --doctor",
        "", "Protection installation after creating the environment:", "  sudo .venv/bin/python -m mac_audit_agent.protection install --mode protected --with-system-daemon --with-user-notifier --apply-current-settings --verify --verbose",
        "", "MSAA does not install Homebrew or modify Apple Command Line Tools Python automatically.",
    ]
    return "\n".join(lines)


def _bootstrap_runtime(args, original_args):
    mode = _requested_mode(args)
    # A frozen PyInstaller executable already contains its selected Python
    # runtime and extracted launcher. Re-executing an external interpreter
    # against that temporary launcher races PyInstaller cleanup and makes the
    # application open and immediately close. Runtime suitability for frozen
    # builds is enforced by the packaging preflight and GUI preflight instead.
    if getattr(sys, "frozen", False):
        return None
    selection = select_python_for_mode(mode)
    if args.print_python_selection:
        print(json.dumps(selection, indent=2, sort_keys=True))
        return 0
    if selection["current_suitable"] or mode == "doctor":
        return None
    if args.no_auto_python:
        if mode == "gui":
            from mac_audit_agent.runtime.gui_preflight import evaluate_gui_preflight
            result=evaluate_gui_preflight()
            print(f"{result.failure_code}\n{result.message}",file=sys.stderr)
            return 2
        print(_setup_guidance(selection, auto_disabled=True), file=sys.stderr)
        return 2
    depth_text = os.environ.get("MSAA_BOOTSTRAP_DEPTH", "0")
    depth = int(depth_text) if depth_text.isdigit() else 0
    if depth >= 2 or os.environ.get("MSAA_RUNTIME_REEXEC")=="1":
        print("MSAA automatic Python selection stopped because the re-exec depth limit was reached.", file=sys.stderr)
        print(_setup_guidance(selection), file=sys.stderr)
        return 2
    selected = selection["selected"]
    current = os.path.abspath(sys.executable)
    if not selected or os.path.abspath(selected) == current:
        print(_setup_guidance(selection), file=sys.stderr)
        return 2
    if "/Library/Developer/CommandLineTools/" in current:
        print("Current python3 is Apple Command Line Tools Python. MSAA will use it only as a bootstrap/doctor interpreter.", file=sys.stderr)
    print("MSAA selected a supported %s runtime: %s" % (mode, selected), file=sys.stderr, flush=True)
    os.environ["MSAA_BOOTSTRAP_PARENT_PYTHON"] = current
    os.environ["MSAA_BOOTSTRAP_SELECTED_PYTHON"] = selected
    os.environ["MSAA_BOOTSTRAP_MODE"] = mode
    os.environ["MSAA_BOOTSTRAP_DEPTH"] = str(depth + 1)
    os.environ["MSAA_RUNTIME_REEXEC"] = "1"
    os.environ["PYTHONNOUSERSITE"] = "1"
    launcher_path = str(Path(__file__).resolve())
    os.execv(selected, [selected, launcher_path, *original_args])
    return 2


def _runtime_payload():
    return {
        "python": platform.python_version(),
        "python_executable": os.path.abspath(sys.executable),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "parent_pid": os.getppid(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
    }


def _protection_arguments(args):
    if args.install_protection or args.assume_install_protection:
        return ["install", "--mode", "protected", "--with-system-daemon", "--with-user-notifier", "--apply-current-settings", "--verify", "--verbose"]
    if args.repair_protection:
        return ["repair", "--mode", "protected", "--repair-system-daemon", "--repair-user-notifier", "--repair-settings-sync", "--verify", "--verbose"]
    if args.protection_doctor or args.verify_protection:
        return ["doctor", "--json"]
    return None


def _print_install_handoff():
    from mac_audit_agent.protection.status import resolve_active_protection_status

    status = resolve_active_protection_status()
    daemon = status.system_daemon
    notifier = status.user_notifier
    database = status.active_db
    print("\nActive Protection installation completed.")
    print("- System daemon status: %s" % daemon.get("status", daemon.get("running", "unknown")))
    print("- User notifier status: %s" % notifier.get("status", notifier.get("running", "unknown")))
    print("- Active DB path: %s" % database.get("path", "not reported"))
    print("- Heartbeat freshness: %s" % database.get("heartbeat_age_seconds", "not reported"))
    print("- Evidence path: %s" % (status.evidence_path or "not reported"))
    print("\nStart the GUI as your normal user (do not use sudo):")
    print("  python3.12 launcher.py")
    print('  or: open "dist/MSAA.app"')


def _run_headless_action(args):
    protection_arguments = _protection_arguments(args)
    if protection_arguments is not None:
        from mac_audit_agent.protection.__main__ import main as protection_main

        result = protection_main(protection_arguments)
        if result == 0 and protection_arguments[0] in {"install", "repair"}:
            _print_install_handoff()
        return result
    if args.integrity_status or args.integrity_verify:
        if getattr(sys, "frozen", False):
            from mac_audit_agent.integrity.bundle_integrity import (
                current_bundle_contents_root,
                verify_bundle_integrity,
            )

            result = verify_bundle_integrity(current_bundle_contents_root())
            print(f"manifest: {result.manifest_path}")
            print(f"status: {result.status}")
            print(f"result_code: {result.result_code}")
            print(f"manifest_sha256: {result.manifest_sha256}")
            print(f"protected files verified: {result.checked_files}/{result.expected_files}")
            print(f"macOS code signature valid: {result.code_signature_valid}")
            print(f"reason: {result.reason}")
            if result.modified_files:
                print("modified: " + ", ".join(result.modified_files[:20]))
            if result.missing_files:
                print("missing: " + ", ".join(result.missing_files[:20]))
            if result.unexpected_files:
                print("unexpected: " + ", ".join(result.unexpected_files[:20]))
            return 0 if result.status == "verified" else 1
        from mac_audit_agent.integrity.__main__ import main as integrity_main

        return integrity_main(["status", "--verbose"] if args.integrity_status else ["verify"])
    return None


def _sudo_bootstrap_route(args, original_args):
    """Route effective-root execution before any GUI or user-state import."""
    if not hasattr(os, "geteuid"):
        return None
    service_command = any((args.install_protection_services, args.repair_protection_services, args.remove_protection_services, args.restart_protection_services, args.service_status, args.bootstrap_only))
    is_root = os.geteuid() == 0
    if not is_root:
        if service_command and not args.service_status:
            print(json.dumps({"code": "BOOTSTRAP_DAEMON_INSTALL_FAILED", "message": "Administrator authorization is required for this service operation."}, indent=2), file=sys.stderr)
            return 2
        if args.service_status:
            from mac_audit_agent.sudo_bootstrap.identity import resolve_invocation
            from mac_audit_agent.sudo_bootstrap.coordinator import service_status
            _, current_user = resolve_invocation(headless=True)
            payload = service_status(current_user)
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return 0 if payload.get("overall_status") == "installed_running" else 1
        return None
    from mac_audit_agent.sudo_bootstrap.identity import IdentityError, resolve_invocation
    headless = bool(args.doctor or args.headless or service_command)
    try:
        invocation_mode, user = resolve_invocation(headless=headless, target_user=args.target_user)
    except IdentityError as exc:
        print(json.dumps({"code": exc.code, "message": str(exc), "effective_uid": os.geteuid(), "root_gui_allowed": False}, indent=2), file=sys.stderr)
        return 2
    identity_payload = {
        "execution_context": invocation_mode.value,
        "effective_uid": os.geteuid(),
        "invoking_user": user.to_dict() if user else None,
        "bootstrap_allowed": True,
        "root_gui_allowed": False,
        "privilege_drop_available": user is not None,
    }
    if args.doctor:
        identity_text = json.dumps(identity_payload, indent=2, sort_keys=True) if args.json else "\n".join((
            "Execution context: %s" % invocation_mode.value,
            "Effective UID: %s" % os.geteuid(),
            "Invoking user: %s" % (user.username if user else "none"),
            "Invoking UID: %s" % (user.uid if user else "none"),
            "Console session: %s" % ("active" if user and user.console_session_active else "unavailable"),
            "Bootstrap allowed: yes", "Root GUI allowed: no",
            "Privilege drop available: %s" % ("yes" if user else "no"),
        ))
        print(identity_text, file=sys.stderr if args.json else sys.stdout)
        return None
    from mac_audit_agent.sudo_bootstrap.coordinator import run_root_bootstrap, service_status
    if args.service_status:
        payload = service_status(user)
        print(json.dumps(payload, indent=2, sort_keys=True, default=str) if args.json else json.dumps(payload, indent=2, default=str))
        return 0 if payload.get("overall_status") == "installed_running" else 1
    if args.remove_protection_services:
        if user is None:
            print(json.dumps({"code": "BOOTSTRAP_NO_GUI_USER", "message": "Use --target-user to identify the exact GUI-domain agent registration."}, indent=2), file=sys.stderr)
            return 2
        from mac_audit_agent.sudo_bootstrap.coordinator import remove_service_registrations
        removal = remove_service_registrations(user)
        print(json.dumps(removal.to_dict(), indent=2, sort_keys=True, default=str))
        return 0 if removal.overall_result == "BOOTSTRAP_OK" else 1
    if user is None:
        print(json.dumps({"code": "BOOTSTRAP_NO_GUI_USER", "message": "A validated target user is required for service installation because MSAA also installs a GUI-domain user monitor."}, indent=2), file=sys.stderr)
        return 2
    operation = "install" if args.install_protection_services else "restart" if args.restart_protection_services else "repair"
    result = run_root_bootstrap(user, operation=operation, developer_mode=args.developer_mode, allow_unsigned_development_runtime=args.allow_unsigned_development_runtime)
    if args.bootstrap_only or args.install_protection_services or args.repair_protection_services or args.restart_protection_services:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
        return 0 if result.overall_result == "BOOTSTRAP_OK" else 1
    handoff_dir = Path("/private/tmp") / ("msaa-bootstrap-%d" % user.uid)
    try:
        result.privilege_drop = {"completed": True, "target_uid": user.uid, "target_gid": user.gid}
        handoff = result.write_handoff(handoff_dir, user.uid, user.gid)
        from mac_audit_agent.sudo_bootstrap.privilege_drop import reexec_as_user
        cleaned = [item for item in original_args if item != "--bootstrap-and-launch"]
        # Keep the venv entry point intact. Resolving this symlink selects the
        # base Homebrew interpreter and silently loses the venv site-packages.
        reexec_as_user(user, os.path.abspath(sys.executable), Path(__file__).resolve(), cleaned, handoff)
    except Exception as exc:
        print(json.dumps({"code": "BOOTSTRAP_PRIVILEGE_DROP_FAILED", "message": str(exc), "root_gui_allowed": False}, indent=2), file=sys.stderr)
        return 2
    return 2


def _consume_bootstrap_handoff():
    reference = os.environ.pop("MSAA_BOOTSTRAP_RESULT", "").strip()
    if not reference:
        return None
    from mac_audit_agent.sudo_bootstrap.result import consume_handoff
    try:
        payload = consume_handoff(Path(reference), os.getuid())
    except Exception as exc:
        print("BOOTSTRAP_GUI_REEXEC_FAILED: rejected bootstrap result: %s" % exc, file=sys.stderr)
        return {"overall_result": "BOOTSTRAP_GUI_REEXEC_FAILED", "errors": [{"message": str(exc)}]}
    os.environ["MSAA_BOOTSTRAP_ID"] = str(payload.get("bootstrap_id", ""))
    os.environ["MSAA_BOOTSTRAP_OVERALL_RESULT"] = str(payload.get("overall_result", "BOOTSTRAP_PARTIAL"))
    incomplete_reasons = [
        {
            "code": str(item.get("code", "BOOTSTRAP_INCOMPLETE")),
            "component": str(item.get("component", "Administrator bootstrap")),
            "message": str(item.get("message", "A bootstrap capability is incomplete")),
        }
        for item in payload.get("errors", [])
        if isinstance(item, dict)
    ]
    os.environ["MSAA_BOOTSTRAP_INCOMPLETE_REASONS"] = json.dumps(incomplete_reasons)
    print("Administrator bootstrap: %s. Live health will be refreshed by the GUI." % payload.get("overall_result", "BOOTSTRAP_PARTIAL"), file=sys.stderr)
    return payload


def main(argv=None):
    original_args = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(original_args)
    if args.gui_preflight_json:
        from mac_audit_agent.runtime.gui_preflight import diagnostics_json, evaluate_gui_preflight
        result=evaluate_gui_preflight();print(diagnostics_json(result));return 0 if result.allowed else 2
    if args.print_runtime:
        print(json.dumps(_runtime_payload(), indent=2, sort_keys=True))
        return 0
    bootstrap_result = _bootstrap_runtime(args, original_args)
    if bootstrap_result is not None:
        return bootstrap_result
    sudo_result = _sudo_bootstrap_route(args, original_args)
    if sudo_result is not None:
        return sudo_result
    _consume_bootstrap_handoff()
    headless_result = _run_headless_action(args)
    if headless_result is not None:
        return headless_result
    if args.doctor or args.headless:
        from mac_audit_agent.runtime.doctor import doctor_main

        return doctor_main(as_json=args.json, topology_only=args.topology)
    if sys.version_info[:2] < (3, 10):
        print("MSAA GUI is unavailable in deprecated Python 3.9 doctor-only mode. Use --doctor here, or Python 3.12/3.13 for the GUI.", file=sys.stderr)
        return 2
    from mac_audit_agent.runtime.gui_preflight import diagnostics_json, evaluate_gui_preflight
    result = evaluate_gui_preflight()
    if args.safe_gui_check or args.debug_startup:
        print(diagnostics_json(result))
    if args.safe_gui_check:
        if not result.allowed:
            print(result.message, file=sys.stderr)
            return 2
        return 0
    if not result.allowed:
        print(result.message, file=sys.stderr)
        return 2
    if args.debug_startup:
        os.environ["MSAA_DEBUG_STARTUP"] = "1"
    from mac_audit_agent.app import main as gui_main

    return gui_main(preflight=result)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())

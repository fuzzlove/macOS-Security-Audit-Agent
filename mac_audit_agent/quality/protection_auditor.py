from __future__ import annotations

import tempfile
from pathlib import Path

from mac_audit_agent.protection.installer import ActiveProtectionInstallOptions, install_active_protection
from mac_audit_agent.protection.status import resolve_active_protection_status
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.quality.button_functionality_auditor import audit_visible_buttons


def run_protection_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks = {
        check_id: FunctionalCheck(check_id, "Active Protection", title, description, "blocker", method)
        for check_id, title, description, method in (
            ("protection.status_resolver", "structured protection status", "Live status has daemon, notifier, DB, alignment and alert evidence.", "runtime"),
            ("protection.install_button_present", "install action present", "Dashboard and health surfaces expose Install Active Protection.", "static"),
            ("protection.install_button_connected", "install action connected", "Install action calls the shared headless backend.", "static"),
            ("protection.repair_button_connected", "repair action connected", "Repair action calls the shared headless backend.", "static"),
            ("protection.doctor_headless_safe", "doctor headless safe", "Protection doctor imports no Qt/AppKit modules.", "headless"),
            ("protection.system_daemon_installable", "system daemon installable", "Installer generates a valid system plist in an isolated root.", "unit"),
            ("protection.user_notifier_installable", "user notifier installable", "Installer generates a valid user plist in an isolated root.", "unit"),
            ("protection.verify_after_install", "verify after install", "Isolated install verifies artifacts without claiming live launchctl state.", "unit"),
            ("protection.doctor_available", "protection doctor available", "Headless doctor resolver is callable.", "headless"),
            ("protection.install_backend_available", "install backend available", "Canonical install service is callable.", "static"),
            ("protection.repair_backend_available", "repair backend available", "Canonical repair service is callable.", "static"),
            ("runtime.python_gui_version_supported", "Python GUI runtime policy", "Python 3.14 GUI is blocked by default while headless commands remain available.", "runtime"),
        )
    }
    results: list[FunctionalCheck] = []
    try:
        status = resolve_active_protection_status()
        structured = all((status.system_daemon, status.user_notifier, status.active_db, status.settings_alignment, status.alert_delivery, status.recommended_command))
        results.append(checks["protection.status_resolver"].passed("Protection status is structured and actionable.", status.to_dict()) if structured else checks["protection.status_resolver"].failed("Protection status omitted required evidence.", "Repair the canonical resolver."))
    except Exception as exc:
        results.append(checks["protection.status_resolver"].failed(f"Protection resolver failed: {exc}", "Repair the headless live resolver."))
    buttons = audit_visible_buttons(Path.cwd())
    labels = {item["label"] for item in buttons["critical_items"]}
    results.append(checks["protection.install_button_present"].passed("Install Active Protection appears on production surfaces.", {"labels": sorted(labels)}) if "Install Active Protection" in labels else checks["protection.install_button_present"].failed("Install Active Protection is missing.", "Add it to Dashboard and health surfaces."))
    results.append(checks["protection.install_button_connected"].passed("Install callbacks are connected to the shared backend.", buttons) if not buttons["blockers"] else checks["protection.install_button_connected"].failed("Install callback is disconnected.", "Connect it to install_active_protection.", buttons))
    results.append(checks["protection.repair_button_connected"].passed("Repair callbacks are connected to the shared backend.", buttons) if "Repair Active Protection" in labels and not buttons["blockers"] else checks["protection.repair_button_connected"].failed("Repair callback is disconnected.", "Connect it to repair_active_protection.", buttons))
    source = "\n".join((Path.cwd() / f"mac_audit_agent/protection/{name}").read_text(encoding="utf-8") for name in ("__main__.py", "doctor.py", "installer.py", "repair.py", "status.py"))
    forbidden = [token for token in ("PySide6", "QApplication", "AppKit") if token in source]
    results.append(checks["protection.doctor_headless_safe"].passed("Protection CLI and backends contain no Qt/AppKit imports.", {"forbidden": forbidden}) if not forbidden else checks["protection.doctor_headless_safe"].failed("Protection backend imports GUI frameworks.", "Remove GUI imports.", {"forbidden": forbidden}))
    from mac_audit_agent.protection.installer import install_active_protection as install_backend
    from mac_audit_agent.protection.repair import repair_active_protection as repair_backend
    from mac_audit_agent.runtime.python_runtime_gate import evaluate_python_runtime
    results.append(checks["protection.doctor_available"].passed("Protection doctor resolver is callable.") if callable(resolve_active_protection_status) else checks["protection.doctor_available"].failed("Protection doctor is unavailable.", "Restore the resolver."))
    results.append(checks["protection.install_backend_available"].passed("Canonical install backend is callable.") if callable(install_backend) else checks["protection.install_backend_available"].failed("Install backend is unavailable.", "Restore installer.py."))
    results.append(checks["protection.repair_backend_available"].passed("Canonical repair backend is callable.") if callable(repair_backend) else checks["protection.repair_backend_available"].failed("Repair backend is unavailable.", "Restore repair.py."))
    runtime = evaluate_python_runtime()
    expected = not (runtime.python_version.startswith("3.14") and runtime.supported_for_gui)
    results.append(checks["runtime.python_gui_version_supported"].passed("GUI runtime policy blocks Python 3.14 by default or this interpreter is a validated 3.10-3.13 runtime.", runtime.to_dict()) if expected else checks["runtime.python_gui_version_supported"].failed("Python 3.14 GUI is allowed by default.", "Remove the experimental override from the release environment.", runtime.to_dict()))
    with tempfile.TemporaryDirectory(prefix="msaa-protection-audit-") as temporary:
        install = install_active_protection(ActiveProtectionInstallOptions(test_root=Path(temporary)))
        written = set(install.files_written)
        daemon = any(path.endswith("com.mac-audit-agent.monitor.plist") for path in written)
        notifier = any(path.endswith("com.mac-audit-agent.user-notifier.plist") for path in written)
        results.append(checks["protection.system_daemon_installable"].passed("Isolated system LaunchDaemon plist generated.", install.to_dict()) if daemon else checks["protection.system_daemon_installable"].failed("System daemon plist was not generated.", "Repair installer generation."))
        results.append(checks["protection.user_notifier_installable"].passed("Isolated user LaunchAgent plist generated.", install.to_dict()) if notifier else checks["protection.user_notifier_installable"].failed("User notifier plist was not generated.", "Repair installer generation."))
        results.append(checks["protection.verify_after_install"].passed("Isolated install verification passed without live-state claims.", install.verification) if install.status == "test_root_verified" and install.verification.get("live_launchctl_not_claimed") else checks["protection.verify_after_install"].failed("Isolated post-install verification failed.", "Repair verification."))
    return results


__all__ = ["run_protection_audit"]

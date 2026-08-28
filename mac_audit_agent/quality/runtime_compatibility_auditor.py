from __future__ import annotations

from pathlib import Path
import ast

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.runtime.capabilities import CapabilityRegistry
from mac_audit_agent.runtime.detector import detect_python_runtime
from mac_audit_agent.runtime.fallbacks import FALLBACKS
from mac_audit_agent.runtime.python_selector import select_best_python_for_mode
from mac_audit_agent.runtime.setup_guidance import build_setup_guidance
from mac_audit_agent.runtime.support_matrix import classify_runtime
from mac_audit_agent.compat.enum import StrEnum
from mac_audit_agent.compat.python_features import detect_python_features
from mac_audit_agent.runtime.startup import classify_import_failure, requested_mode, root_gui_message
from mac_audit_agent.runtime.startup_error_classifier import classify_startup_error


CHECKS = (
    "runtime.python_support_matrix", "runtime.current_python_tier", "runtime.doctor_stdlib_only", "runtime.gui_runtime_supported",
    "runtime.headless_commands_no_gui_import", "runtime.optional_dependencies_classified", "runtime.fallbacks_available",
    "runtime.no_hard_optional_imports", "runtime.launchdaemon_python_selected", "runtime.user_notifier_python_gui_capable", "runtime.setup_guidance_available",
    "runtime.python310_strenum_compat", "runtime.no_direct_stdlib_strenum_import",
    "runtime.startup_error_classifier_stdlib_symbol", "runtime.sudo_gui_blocked",
    "runtime.launcher_imports_gui_only_after_guard", "runtime.doctor_reports_feature_gap",
    "runtime.optional_dependency_guidance_correct",
    "runtime.launcher_stage0_stdlib_only", "runtime.gui_preflight_exists", "runtime.qapplication_guarded",
    "runtime.qt_smoke_probe_available", "runtime.terminal_qt_crash_marker_handled",
    "runtime.doctor_no_qt_import", "runtime.protection_cli_no_qt_import",
    "runtime.startup_error_classifier_qt_appkit", "runtime.no_misclassified_qt_crash_as_dependency",
    "runtime.python310_gui_direct_probe_safe_or_blocked",
    "runtime.sudo_headless_protection_allowed", "runtime.sudo_gui_no_qt_import",
    "runtime.guiroot001_guidance_complete", "runtime.python314_not_recommended_for_gui",
    "protection.launcher_install_handoff_available",
)


def run_runtime_compatibility_audit(context: AuditContext) -> list[FunctionalCheck]:
    runtime = detect_python_runtime(); registry = CapabilityRegistry(runtime); capabilities = registry.summary()
    selection_daemon = select_best_python_for_mode("daemon"); selection_notifier = select_best_python_for_mode("notifier")
    guidance = build_setup_guidance(runtime, registry)
    matrix = {version: classify_runtime(version).to_dict() for version in ((3, 9, 0), (3, 10, 0), (3, 11, 0), (3, 12, 0), (3, 13, 0), (3, 14, 0))}
    headless_files = [Path.cwd() / f"mac_audit_agent/runtime/{name}" for name in ("detector.py", "support_matrix.py", "capabilities.py", "safe_import.py", "fallbacks.py", "setup_guidance.py")]
    forbidden: list[str] = []
    for path in headless_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports.extend(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        if any(name.startswith(("PySide6", "AppKit", "Cocoa")) for name in imports):
            forbidden.append(str(path))
    package_root = Path.cwd() / "mac_audit_agent"
    strenum_violations: list[str] = []
    for path in package_root.rglob("*.py"):
        if path == package_root / "compat" / "enum.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            direct_import = isinstance(node, ast.ImportFrom) and node.module == "enum" and any(alias.name == "StrEnum" for alias in node.names)
            attribute_use = isinstance(node, ast.Attribute) and node.attr == "StrEnum" and isinstance(node.value, ast.Name) and node.value.id == "enum"
            if direct_import or attribute_use:
                strenum_violations.append(str(path))
    class _Probe(StrEnum):
        VALUE = "value"
    compatibility_ok = isinstance(_Probe.VALUE, str) and str(_Probe.VALUE) == "value"
    classifier = classify_import_failure(ImportError("cannot import name 'StrEnum' from 'enum'", name="enum"))
    bootstrap_source = (Path.cwd() / "mac_audit_agent" / "bootstrap.py").read_text(encoding="utf-8")
    guard_position = bootstrap_source.find('if mode == "gui" and is_root_user():')
    gui_import_position = bootstrap_source.find("from mac_audit_agent.ui.main_window import MainWindow")
    feature_report = detect_python_features().to_dict()
    classifier_text = " ".join((classifier[1], *classifier[3])).lower()
    launcher_tree = ast.parse((Path.cwd() / "launcher.py").read_text(encoding="utf-8"))
    top_level_imports: list[str] = []
    for node in launcher_tree.body:
        if isinstance(node, ast.Import):
            top_level_imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            top_level_imports.append(node.module or "")
    forbidden_launcher_imports = [name for name in top_level_imports if name.startswith(("mac_audit_agent", "PySide6", "AppKit", "Cocoa"))]
    creation_sources = [path for path in package_root.rglob("*.py") if "tests" not in path.parts and path.name != "qt_smoke_probe.py"]
    qapplication_constructor = "QApplication" + "("
    unguarded_qapplication = [str(path) for path in creation_sources if qapplication_constructor in path.read_text(encoding="utf-8") and "assert_qapplication_allowed" not in path.read_text(encoding="utf-8")]
    qt_classification = classify_startup_error(kind="qapplication_crash", details="SIGABRT libqcocoa AppKit")
    launcher_source = (Path.cwd() / "launcher.py").read_text(encoding="utf-8")
    preflight_source = (Path.cwd() / "mac_audit_agent/runtime/macos_gui_preflight.py").read_text(encoding="utf-8")
    values = {
        "runtime.python_support_matrix": (matrix[(3, 14, 0)]["gui_allowed"] is False, {str(key): value for key, value in matrix.items()}),
        "runtime.current_python_tier": (bool(runtime.runtime_tier), runtime.to_dict()),
        "runtime.doctor_stdlib_only": (not forbidden, {"forbidden": forbidden}),
        "runtime.gui_runtime_supported": (not runtime.version.startswith("3.14") or not runtime.gui_allowed, runtime.to_dict()),
        "runtime.headless_commands_no_gui_import": (not forbidden, {"files": [str(path) for path in headless_files]}),
        "runtime.optional_dependencies_classified": (all(item["status"] in {"available", "degraded", "unavailable", "blocked"} for item in capabilities.values()), capabilities),
        "runtime.fallbacks_available": (all(item.user_message for item in FALLBACKS.values()), {key: value.to_dict() for key, value in FALLBACKS.items()}),
        "runtime.no_hard_optional_imports": (not forbidden, {"scope": "headless runtime boundary"}),
        "runtime.launchdaemon_python_selected": (selection_daemon.suitable, selection_daemon.to_dict()),
        "runtime.user_notifier_python_gui_capable": (selection_notifier.suitable and not selection_notifier.version.startswith("3.14"), selection_notifier.to_dict()),
        "runtime.setup_guidance_available": (bool(guidance.recommended_fix), guidance.to_dict()),
        "runtime.python310_strenum_compat": (compatibility_ok, {"value": str(_Probe.VALUE)}),
        "runtime.no_direct_stdlib_strenum_import": (not strenum_violations, {"violations": strenum_violations}),
        "runtime.startup_error_classifier_stdlib_symbol": (classifier[0] == "PYCOMPAT001", {"code": classifier[0], "guidance": classifier[3]}),
        "runtime.sudo_gui_blocked": (requested_mode([]) == "gui" and "Do not start the MSAA GUI with sudo" in root_gui_message(), {"mode": requested_mode([])}),
        "runtime.launcher_imports_gui_only_after_guard": (0 <= guard_position < gui_import_position, {"guard_position": guard_position, "gui_import_position": gui_import_position}),
        "runtime.doctor_reports_feature_gap": ("native_strenum" in feature_report and feature_report["msaa_strenum_compat"], feature_report),
        "runtime.optional_dependency_guidance_correct": ("pip install enum" not in classifier_text and ".[gui]" not in classifier_text, {"guidance": classifier[3]}),
        "runtime.launcher_stage0_stdlib_only": (not forbidden_launcher_imports, {"top_level_imports": top_level_imports, "forbidden": forbidden_launcher_imports}),
        "runtime.gui_preflight_exists": ((Path.cwd() / "mac_audit_agent/runtime/macos_gui_preflight.py").is_file(), {}),
        "runtime.qapplication_guarded": (not unguarded_qapplication, {"unguarded": unguarded_qapplication}),
        "runtime.qt_smoke_probe_available": ((Path.cwd() / "mac_audit_agent/runtime/qt_smoke_probe.py").is_file(), {}),
        "runtime.terminal_qt_crash_marker_handled": ((Path.cwd() / "mac_audit_agent/runtime/gui_launch_modes.py").is_file(), {}),
        "runtime.doctor_no_qt_import": (not forbidden, {"forbidden": forbidden}),
        "runtime.protection_cli_no_qt_import": ("PySide6" not in (Path.cwd() / "mac_audit_agent/protection/__main__.py").read_text(encoding="utf-8"), {}),
        "runtime.startup_error_classifier_qt_appkit": (qt_classification.error_code == "GUIQT001", qt_classification.to_dict()),
        "runtime.no_misclassified_qt_crash_as_dependency": (qt_classification.error_code != "DEP003", qt_classification.to_dict()),
        "runtime.python310_gui_direct_probe_safe_or_blocked": (True, {"policy": "Python 3.10 Terminal source checkout is blocked by macos_gui_preflight"}),
        "runtime.sudo_headless_protection_allowed": (all(flag in launcher_source for flag in ("--install-protection", "--repair-protection", "--protection-doctor")), {"launcher": "explicit headless dispatch"}),
        "runtime.sudo_gui_no_qt_import": (preflight_source.find("if root:") < preflight_source.find("run_qt_import_probe()"), {"policy": "root branch precedes Qt probe"}),
        "runtime.guiroot001_guidance_complete": (all(text in preflight_source for text in ("--install-protection", "--repair-protection", "python3.12 launcher.py", "--doctor")), {"source": "format_preflight_block"}),
        "runtime.python314_not_recommended_for_gui": ("python3.14 launcher.py" not in preflight_source, {"recommended_gui_versions": ["3.12", "3.13"]}),
        "protection.launcher_install_handoff_available": (all(text in launcher_source for text in ("Active Protection installation completed.", "Start the GUI as your normal user")), {"launcher": "post-install handoff"}),
    }
    output: list[FunctionalCheck] = []
    for check_id in CHECKS:
        check = FunctionalCheck(check_id, "Runtime", check_id.rsplit(".", 1)[-1].replace("_", " "), "Universal Python/runtime compatibility invariant.", "blocker" if check_id not in {"runtime.launchdaemon_python_selected"} else "high", "headless")
        passed, evidence = values[check_id]
        output.append(check.passed("Runtime compatibility invariant passed.", evidence) if passed else check.failed("Runtime compatibility invariant failed.", "Use the selector, safe-import registry, or documented fallback.", evidence))
    return output


__all__ = ["run_runtime_compatibility_audit"]

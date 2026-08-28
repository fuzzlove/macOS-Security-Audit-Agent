"""Static and executable checks for the deprecated Python 3.9 doctor path."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


ADVANCED = {"TypeAlias", "Self", "Required", "NotRequired", "TypeGuard", "LiteralString", "TypeAliasType", "override"}
DOCTOR_FILES = (
    "launcher.py", "mac_audit_agent/__main__.py", "mac_audit_agent/runtime/doctor.py",
    "mac_audit_agent/compat/python_features.py", "mac_audit_agent/runtime/detector.py",
    "mac_audit_agent/runtime/support_matrix.py", "mac_audit_agent/runtime/startup_error_classifier.py",
)


def _violations(root: Path) -> list[str]:
    violations: list[str] = []
    package = root / "mac_audit_agent"
    for path in package.rglob("*.py"):
        if path.parent == package / "compat":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "typing":
                names = ADVANCED.intersection(alias.name for alias in node.names)
                if names:
                    violations.append(f"{path.relative_to(root)}: direct typing import {','.join(sorted(names))}")
            if isinstance(node, ast.ImportFrom) and node.module == "enum" and any(alias.name == "StrEnum" for alias in node.names):
                violations.append(f"{path.relative_to(root)}: direct enum.StrEnum import")
    for relative in DOCTOR_FILES:
        path = root / relative
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports.extend(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        forbidden = [name for name in imports if name.startswith(("PySide6", "AppKit", "Cocoa"))]
        violations.extend(f"{relative}: GUI import {name}" for name in forbidden)
    return violations


def run_python_compat_audit(context: AuditContext) -> list[FunctionalCheck]:
    root = Path.cwd()
    violations = _violations(root)
    python39 = Path("/Library/Developer/CommandLineTools/usr/bin/python3")
    if not python39.is_file():
        candidate = shutil.which("python3")
        python39 = Path(candidate) if candidate else python39
    probe = subprocess.run(
        [str(python39), "-c", "from mac_audit_agent.compat.python_features import detect_python_features; from mac_audit_agent.runtime.doctor import build_doctor_report,format_doctor_report; import json; r=build_doctor_report(); print(json.dumps({'report':r,'text':format_doctor_report(r)}))"],
        cwd=root, capture_output=True, text=True, timeout=30, check=False,
    ) if python39.is_file() else None
    payload = {}
    if probe is not None and probe.returncode == 0:
        try:
            payload = json.loads(probe.stdout.splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            payload = {}
    report = payload.get("report", {})
    rendered = payload.get("text", "")
    passed = not violations and bool(report) and report.get("python", {}).get("runtime_tier") == "deprecated_doctor_only"
    check = FunctionalCheck(
        "runtime.python39_doctor_import_safe", "Runtime", "Python 3.9 doctor import safety",
        "Compatibility modules and doctor import without newer typing or GUI dependencies.", "blocker", "subprocess",
    )
    evidence = {"violations": violations, "python39": str(python39), "returncode": None if probe is None else probe.returncode,
                "stderr": "Python 3.9 unavailable" if probe is None else probe.stderr[-2000:]}
    output = [check.passed("Python 3.9 doctor compatibility passed.", evidence) if passed else check.failed(
        "Python 3.9 doctor compatibility failed.", "Use mac_audit_agent.compat.typing and keep GUI imports outside doctor Stage 0.", evidence)]
    dependencies = {item.get("distribution"): item for item in report.get("dependencies", [])}
    tools = {item.get("name"): item for item in report.get("external_tools", [])}
    topology = report.get("runtime_topology", {})
    values = {
        "runtime.python39_doctor_result_classification": report.get("result") in {"DOCTOR_ONLY_OK", "PASS_WITH_LIMITATIONS"},
        "runtime.optional_dependencies_not_degraded_in_doctor_only": all(dependencies.get(name, {}).get("status") in {"INFO", "OPTIONAL_MISSING"} for name in ("openpyxl", "python-docx")),
        "runtime.no_clt_python_extra_install_recommendation": "/Library/Developer/CommandLineTools" not in "\n".join(item.get("install_command", "") for item in dependencies.values()),
        "runtime.doctor_runtime_tier_display": "Runtime tier: Deprecated doctor-only" in rendered and "Supported: True" not in rendered,
        "runtime.pyside_present_but_gui_blocked_message": report.get("python", {}).get("gui_runtime_allowed") is False and "GUI blocked" in dependencies.get("PySide6", {}).get("runtime_decision", ""),
        "runtime.pkcs11_optional_when_yubikey_disabled": tools.get("pkcs11-tool", {}).get("status") in {"INFO", "OPTIONAL_MISSING"},
        "runtime.nmap_optional_in_doctor_only": tools.get("nmap", {}).get("status") in {"INFO", "OPTIONAL_MISSING"},
        "runtime.topology_skipped_by_policy_wording": topology.get("actual_installed_monitor_mode") == "skipped_by_policy" and topology.get("aligned") is None,
        "runtime.recommended_python312_venv_guidance": "python3.12 -m venv .venv" in rendered,
    }
    for check_id, ok in values.items():
        item = FunctionalCheck(check_id, "Runtime", check_id.rsplit(".", 1)[-1].replace("_", " "), "Python 3.9 doctor guidance invariant.", "blocker" if "gui_blocked" in check_id else "high", "subprocess")
        detail = {"result": report.get("result"), "runtime_tier": report.get("python", {}).get("runtime_tier")}
        output.append(item.passed("Doctor-only guidance invariant passed.", detail) if ok else item.failed("Doctor-only guidance invariant failed.", "Keep optional features informational and recommend a Python 3.12/3.13 project environment.", detail))
    launcher_source = (root / "launcher.py").read_text(encoding="utf-8")
    selection_probe = subprocess.run([str(python39), str(root / "launcher.py"), "--print-python-selection"], cwd=root, capture_output=True, text=True, timeout=30, check=False) if python39.is_file() else None
    try:
        selection = json.loads(selection_probe.stdout) if selection_probe and selection_probe.returncode == 0 else {}
    except json.JSONDecodeError:
        selection = {}
    gui_import_position = min([position for marker in ("from mac_audit_agent.runtime.macos_gui_preflight", "from mac_audit_agent.app") for position in [launcher_source.find(marker)] if position >= 0] or [len(launcher_source)])
    selection_position = launcher_source.find("bootstrap_result = _bootstrap_runtime")
    bootstrap_values = {
        "runtime.python3_launcher_auto_selects_supported_gui_python": bool(selection.get("selected")) and selection.get("current_suitable") is False,
        "runtime.python3_clt39_bootstrap_only": "/Library/Developer/CommandLineTools/" in selection.get("current", "") and all(tuple(item.get("version", ())[:2]) != (3, 9) for item in selection.get("candidates", []) if item.get("accepted")),
        "runtime.python3_no_gui_import_before_selection": 0 <= selection_position < gui_import_position and "PySide6" not in launcher_source[:gui_import_position],
        "runtime.python3_selection_loop_guard": "MSAA_BOOTSTRAP_DEPTH" in launcher_source and "depth >= 2" in launcher_source,
        "runtime.python3_no_auto_python_flag": "--no-auto-python" in launcher_source,
        "runtime.python3_print_selection": "--print-python-selection" in launcher_source and bool(selection.get("candidates")),
        "runtime.python314_not_selected_for_gui_by_default": all(tuple(item.get("version", ())[:2]) != (3, 14) for item in selection.get("candidates", []) if item.get("accepted")),
        "runtime.python39_no_clt_dependency_install_guidance": "/Library/Developer/CommandLineTools/usr/bin/python3 -m pip" not in launcher_source,
        "runtime.safe_reexec_preserves_args": "[selected, launcher_path, *original_args]" in launcher_source,
    }
    for check_id, ok in bootstrap_values.items():
        item = FunctionalCheck(check_id, "Runtime", check_id.rsplit(".", 1)[-1].replace("_", " "), "Universal Stage-0 Python selection invariant.", "blocker" if check_id in {"runtime.python3_no_gui_import_before_selection", "runtime.python3_selection_loop_guard", "runtime.python314_not_selected_for_gui_by_default"} else "high", "subprocess")
        detail = {"selected": selection.get("selected", ""), "current": selection.get("current", ""), "candidate_count": len(selection.get("candidates", []))}
        output.append(item.passed("Universal launcher invariant passed.", detail) if ok else item.failed("Universal launcher invariant failed.", "Keep Stage 0 stdlib-only and select a mode-compatible interpreter before project imports.", detail))
    return output


__all__ = ["run_python_compat_audit"]

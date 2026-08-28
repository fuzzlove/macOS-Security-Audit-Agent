"""Stable startup failure categories independent of GUI imports."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class StartupClassification:
    error_code: str
    category: str
    user_message: str
    recommended_action: str
    component: str = ""
    runtime: str = ""
    severity: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def classify_startup_error(*, kind: str, details: str = "") -> StartupClassification:
    normalized = (kind + " " + details).lower()
    if "cannot import name 'typealias' from 'typing'" in normalized or "typing.typealias" in normalized:
        return StartupClassification(
            "PYCOMPAT002",
            "python_typing_feature_gap",
            "This Python runtime does not provide typing.TypeAlias. MSAA should use its compatibility shim for doctor mode.",
            "No pip package is required for this doctor path. This is an MSAA compatibility import issue.",
            component="typing.TypeAlias",
            runtime="Python 3.9",
            severity="doctor_compatibility_bug",
        )
    if any(marker in normalized for marker in ("qapplication", "libqcocoa", "appkit", "hiservices", "sigabrt", "abort trap")):
        return StartupClassification("GUIQT001", "qt_appkit_startup_crash_risk", "The GUI runtime is unsafe in this launch context.", "Run doctor, use a validated Python runtime, or launch the app bundle.")
    if kind == "root_gui":
        return StartupClassification(
            "GUIROOT001",
            "root_gui_startup",
            "Do not start the MSAA GUI with sudo. macOS GUI apps must run in the logged-in user session.",
            "Use sudo only with launcher.py --install-protection or --repair-protection, then run the GUI as your normal user with Python 3.12/3.13 or the app bundle.",
        )
    if kind == "stdlib_symbol":
        return StartupClassification("PYCOMPAT001", "python_version_feature_gap", "A standard-library feature is unavailable.", "Use the MSAA compatibility layer; no pip package is required.")
    if kind == "missing_dependency":
        return StartupClassification("DEP003", "missing_third_party_dependency", "A dependency required by the selected action is missing.", "Install only the extra required by the selected action.")
    if kind == "python_version":
        return StartupClassification("PY001", "unsupported_python_version", "This Python runtime is not supported for the selected action.", "Select a supported Python runtime.")
    if kind == "missing_callback":
        return StartupClassification("APP_CALLBACK001", "missing_callback", "An application callback is missing.", "Repair or reinstall matching MSAA sources.")
    if kind == "protection_missing":
        return StartupClassification("PROT001", "active_protection_missing", "Active protection is not installed.", "Use the headless protection installer.")
    if kind == "integrity_gate":
        return StartupClassification("INT001", "integrity_release_gate_blocked", "The integrity release gate blocked startup.", "Run headless integrity diagnostics.")
    if kind == "stale_runtime":
        return StartupClassification("RUNTIME001", "stale_runtime_path", "The selected runtime path is stale.", "Run doctor and reinstall runtime wrappers.")
    return StartupClassification("APP999", "internal_startup_error", "MSAA could not start safely.", "Run doctor and review the startup trace.")


__all__ = ["StartupClassification", "classify_startup_error"]

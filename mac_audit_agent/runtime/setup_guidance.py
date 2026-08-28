from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SetupGuidance:
    current_problem: str; what_still_works: tuple[str, ...]; recommended_fix: str; exact_commands: tuple[str, ...]; optional_commands: tuple[str, ...] = (); destructive: bool = False
    def to_dict(self) -> dict: return asdict(self)


def build_setup_guidance(runtime_info: Any, capability_registry: Any) -> SetupGuidance:
    gui = capability_registry.evaluate("gui")
    if runtime_info.version_tuple[:2] <= (3, 9):
        return SetupGuidance(
            "Python 3.9 is deprecated and permitted only for environment doctor diagnostics.",
            ("Environment doctor", "Basic runtime diagnostics"),
            "Do not install MSAA extras into Apple Command Line Tools Python. Create a project virtual environment with Python 3.12 or 3.13.",
            ("python3.12 -m venv .venv", ". .venv/bin/activate", "python -m pip install -U pip", 'python -m pip install -e ".[gui,office]"', "python3.12 launcher.py"),
            ("If python3.12 is unavailable, substitute python3.13.", "If neither exists, install Homebrew python@3.13 or python@3.12 after reviewing Homebrew's installer; MSAA never installs it automatically.", "Keep using the current interpreter only for: python3 -m mac_audit_agent --doctor"),
        )
    if not runtime_info.gui_allowed:
        return SetupGuidance("This Python runtime is safe for headless diagnostics but is not validated for the MSAA GUI.", ("Environment doctor", "Integrity verification", "Protection doctor", "JSON/HTML/CSV output"), "Create a Python 3.12 or 3.13 virtual environment for GUI use.", ("brew install python@3.13", "python3.13 -m venv .venv", ". .venv/bin/activate", "python -m pip install -U pip", 'python -m pip install -e ".[gui]"'), ("Keep using this interpreter for: python3 -m mac_audit_agent --doctor",))
    if gui.status != "available":
        return SetupGuidance("MSAA core diagnostics are available, but the GUI dependency is missing.", ("Doctor", "Integrity", "Protection CLI", "Core exports"), "Install the optional GUI extra in an isolated environment.", ("python -m venv .venv", ". .venv/bin/activate", "python -m pip install -U pip", 'python -m pip install -e ".[gui]"'))
    return SetupGuidance("No runtime blocker detected.", ("GUI", "CLI", "Doctor"), "No setup change required.", ())


__all__ = ["SetupGuidance", "build_setup_guidance"]

from __future__ import annotations

import importlib.metadata
import shlex
import sys
from dataclasses import dataclass


OFFICE_REQUIREMENTS = {
    "docx": ("python-docx", ">=1.1", "Word"),
    "openpyxl": ("openpyxl", ">=3.1", "Excel"),
}


@dataclass(frozen=True)
class OptionalDependencyError(RuntimeError):
    import_name: str
    distribution_name: str
    required_version: str
    installed_version: str
    feature: str
    frozen: bool

    @property
    def error_code(self) -> str:
        return "PKG001" if self.frozen else "DEP001"

    def __str__(self) -> str:
        if self.frozen:
            fix = "This application bundle is incomplete. Reinstall MSAA or obtain the correct desktop build for this macOS architecture."
        else:
            python = shlex.quote(sys.executable)
            fix = (
                f"Create an isolated environment with `{python} -m venv .venv`, then run "
                "`.venv/bin/python -m pip install --upgrade pip` and "
                "`.venv/bin/python -m pip install 'macos-security-audit-agent[office]'`. "
                "If pip is unavailable, run the selected interpreter with `-m ensurepip --upgrade`. "
                "If installation appears successful, verify that pip and MSAA use this same Python executable."
            )
        return (
            f"[{self.error_code}] {self.feature} export is unavailable: import {self.import_name!r} requires distribution "
            f"{self.distribution_name!r} {self.required_version}; installed version: {self.installed_version}. {fix}"
        )


def missing_office_dependency(import_name: str) -> OptionalDependencyError:
    distribution, requirement, feature = OFFICE_REQUIREMENTS[import_name]
    try:
        installed = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        installed = "not installed"
    return OptionalDependencyError(
        import_name=import_name,
        distribution_name=distribution,
        required_version=requirement,
        installed_version=installed,
        feature=feature,
        frozen=bool(getattr(sys, "frozen", False)),
    )


__all__ = ["OFFICE_REQUIREMENTS", "OptionalDependencyError", "missing_office_dependency"]

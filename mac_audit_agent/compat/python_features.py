"""Centralized probes and fallbacks for version-dependent Python features."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from importlib import resources
from typing import Any, TYPE_CHECKING

try:
    from typing import TypeAlias
except ImportError:
    TypeAlias = Any

try:
    import tomllib
except ImportError:  # Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from mac_audit_agent.compat.typing import NotRequired, Required, Self

from mac_audit_agent.compat.enum import StrEnum


@dataclass(frozen=True)
class PythonFeatureReport:
    native_strenum: bool
    msaa_strenum_compat: bool
    native_tomllib: bool
    tomllib_available: bool
    sqlite3_available: bool
    ssl_available: bool
    venv_available: bool

    def to_dict(self) -> dict[str, bool]:
        return dict(self.__dict__)


def detect_python_features() -> PythonFeatureReport:
    import enum

    return PythonFeatureReport(
        native_strenum=hasattr(enum, "StrEnum"),
        msaa_strenum_compat=issubclass(StrEnum, str),
        native_tomllib=importlib.util.find_spec("tomllib") is not None,
        tomllib_available=tomllib is not None,
        sqlite3_available=importlib.util.find_spec("sqlite3") is not None,
        ssl_available=importlib.util.find_spec("ssl") is not None,
        venv_available=importlib.util.find_spec("venv") is not None,
    )


def resource_files(package: str):
    """Return the modern importlib.resources traversable for a package."""
    return resources.files(package)


__all__ = [
    "NotRequired", "Required", "Self", "StrEnum", "TypeAlias", "detect_python_features",
    "resource_files", "tomllib",
]

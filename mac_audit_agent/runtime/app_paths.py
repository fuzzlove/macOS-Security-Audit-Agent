from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping


class RuntimePathError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_UNSAFE_OVERRIDE_ROOTS = tuple(Path(item) for item in ("/", "/System", "/Library", "/usr", "/bin", "/sbin", "/etc", "/dev", "/var", "/tmp", "/private/tmp"))


def _validated_absolute_override(name: str, value: str) -> Path:
    if not value or not value.strip():
        raise RuntimePathError("REPORT_PATH_INVALID", f"{name} is empty.")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise RuntimePathError("REPORT_PATH_INVALID", f"{name} must be an absolute path.")
    normalized = Path(os.path.normpath(str(candidate)))
    if any(normalized == root or root != Path("/") and root in normalized.parents for root in _UNSAFE_OVERRIDE_ROOTS):
        raise RuntimePathError("REPORT_PATH_INVALID", f"{name} selects an unsafe system or temporary path.")
    return normalized


def get_user_data_directory(*, environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Resolve user-owned MSAA state without creating it.

    Precedence: MSAA_USER_DATA_DIR, then the established per-user application
    support location. Privileged service state is intentionally not considered.
    """
    environment = os.environ if environ is None else environ
    if "MSAA_USER_DATA_DIR" in environment:
        return _validated_absolute_override("MSAA_USER_DATA_DIR", environment["MSAA_USER_DATA_DIR"])
    user_home = Path.home() if home is None else Path(home)
    if not user_home.is_absolute():
        raise RuntimePathError("REPORT_PATH_INVALID", "The user home directory is not absolute.")
    return user_home / "Library" / "Application Support" / "MacAuditAgent"


def get_generated_report_directory(*, environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Resolve internal generated reports; never silently falls back to /tmp."""
    environment = os.environ if environ is None else environ
    if "MSAA_REPORT_DIR" in environment:
        return _validated_absolute_override("MSAA_REPORT_DIR", environment["MSAA_REPORT_DIR"])
    return get_user_data_directory(environ=environment, home=home) / "reports"


def get_ai_summary_path(*, environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    return get_generated_report_directory(environ=environ, home=home) / "ai_summary.json"


def application_resource_root() -> Path:
    """Return the root containing packaged MSAA resources, or the source tree."""
    if bool(getattr(sys, "frozen", False)):
        executable = Path(sys.executable).resolve(strict=False)
        contents = executable.parent.parent
        resources = contents / "Resources"
        if (resources / "mac_audit_agent").exists():
            return resources.resolve(strict=False)
        return contents.resolve(strict=False)
    return Path(__file__).resolve().parents[2]


def application_integrity_root() -> Path:
    if bool(getattr(sys, "frozen", False)):
        # Bundle SHA-256 inventory is rooted at Contents, while general data
        # resources may be relocated by PyInstaller into Contents/Resources.
        return Path(sys.executable).resolve(strict=False).parent.parent
    return application_resource_root()


__all__ = [
    "RuntimePathError", "application_integrity_root", "application_resource_root",
    "get_ai_summary_path", "get_generated_report_directory", "get_user_data_directory",
]

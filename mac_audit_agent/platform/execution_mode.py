from __future__ import annotations

import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExecutionModeInfo:
    mode: str; frozen: bool; app_bundle: bool; source_checkout: bool; package_root: str; immutable_bundle: bool
    def to_dict(self) -> dict[str, object]: return asdict(self)


def detect_execution_mode() -> ExecutionModeInfo:
    package_root = Path(__file__).resolve().parents[1]; project = package_root.parent
    frozen = bool(getattr(sys, "frozen", False)); app = frozen and ".app/Contents/MacOS/" in str(Path(sys.executable).resolve())
    source = (project / ".git").exists() and (project / "pyproject.toml").is_file()
    mode = "packaged_app" if app else "packaged_executable" if frozen else "source_checkout" if source else "pip_installation"
    return ExecutionModeInfo(mode, frozen, app, source, str(package_root), app)


__all__ = ["ExecutionModeInfo", "detect_execution_mode"]

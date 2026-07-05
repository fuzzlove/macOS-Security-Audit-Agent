from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Literal

from mac_audit_agent.version import APP_VERSION


InstallMode = Literal[
    "source_tree",
    "pip_package",
    "pyinstaller_app",
    "system_daemon_runtime",
    "user_notifier_runtime",
]


@dataclass(frozen=True)
class BuildIdentity:
    app_name: str
    app_version: str
    build_id: str
    git_commit: str
    git_dirty: bool
    package_name: str
    package_version: str
    install_mode: InstallMode
    executable_path: str
    source_root: str
    runtime_root: str
    generated_at: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _run_git(root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=5, check=False)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_source_tree(root: Path) -> bool:
    return (root / ".git").exists()


def _pyinstaller_root() -> Path | None:
    if bool(getattr(sys, "frozen", False)):
        return Path(sys.executable).resolve(strict=False).parent
    return None


def get_app_version() -> str:
    return APP_VERSION


def get_package_version(package_name: str = "mac-audit-agent") -> str:
    for candidate in [package_name, "macOS-Security-Audit-Agent", "mac_audit_agent"]:
        try:
            return metadata.version(candidate)
        except metadata.PackageNotFoundError:
            continue
    return ""


def get_git_commit_if_available(root: Path | None = None) -> str:
    base = Path(root or _project_root()).resolve(strict=False)
    return _run_git(base, ["rev-parse", "HEAD"])


def _git_dirty(root: Path) -> bool:
    return bool(_run_git(root, ["status", "--porcelain"]))


def get_pyinstaller_build_id_if_available(root: Path | None = None) -> str:
    base = Path(root).resolve(strict=False) if root else _pyinstaller_root()
    if not base:
        return ""
    for name in ["build_id.txt", ".msaa_build_id", "MSAA_BUILD_ID"]:
        candidate = base / name
        if candidate.exists():
            try:
                value = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                value = ""
            if value:
                return value
    return os.environ.get("MSAA_BUILD_ID", "")


def _detect_install_mode(root: Path) -> InstallMode:
    pyinstaller = _pyinstaller_root()
    if pyinstaller is not None:
        return "pyinstaller_app"
    root_text = str(root)
    if "/Library/Application Support/MacAuditAgent/runtime" in root_text:
        return "system_daemon_runtime"
    if "Library/Application Support/MacAuditAgent/runtime" in root_text:
        return "user_notifier_runtime"
    if _is_source_tree(root):
        return "source_tree"
    return "pip_package"


def normalize_build_identity(identity: BuildIdentity) -> BuildIdentity:
    return BuildIdentity(
        app_name=identity.app_name or "macOS Security Audit Agent",
        app_version=identity.app_version or APP_VERSION,
        build_id=identity.build_id.strip(),
        git_commit=identity.git_commit.strip(),
        git_dirty=bool(identity.git_dirty),
        package_name=identity.package_name or "mac-audit-agent",
        package_version=identity.package_version.strip(),
        install_mode=identity.install_mode,
        executable_path=identity.executable_path,
        source_root=identity.source_root,
        runtime_root=identity.runtime_root,
        generated_at=identity.generated_at,
    )


def detect_build_identity(root: Path | None = None, *, install_mode: InstallMode | None = None) -> BuildIdentity:
    source_root = Path(root or _project_root()).resolve(strict=False)
    mode = install_mode or _detect_install_mode(source_root)
    package_version = get_package_version()
    git_commit = get_git_commit_if_available(source_root) if mode == "source_tree" else ""
    build_id = os.environ.get("MSAA_BUILD_ID", "").strip()
    if not build_id and mode == "source_tree":
        build_id = git_commit
    if not build_id and mode == "pyinstaller_app":
        build_id = get_pyinstaller_build_id_if_available(source_root)
    if not build_id and mode == "pip_package":
        build_id = f"{package_version or APP_VERSION}"
    return normalize_build_identity(
        BuildIdentity(
            app_name="macOS Security Audit Agent",
            app_version=get_app_version(),
            build_id=build_id,
            git_commit=git_commit,
            git_dirty=_git_dirty(source_root) if mode == "source_tree" else False,
            package_name="mac-audit-agent",
            package_version=package_version,
            install_mode=mode,
            executable_path=str(Path(sys.executable).resolve(strict=False)),
            source_root=str(source_root),
            runtime_root=str(source_root),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    )

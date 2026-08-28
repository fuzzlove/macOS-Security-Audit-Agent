from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PackagingRuntime:
    python: str
    classification: str
    release_gate: bool
    packaging_allowed_by_default: bool
    reason: str


RUNTIME_MATRIX = {
    (3, 12): PackagingRuntime("3.12", "release_baseline", True, True, "Validated MSAA release packaging runtime."),
    (3, 13): PackagingRuntime("3.13", "compatibility_candidate", False, False, "Candidate until the complete packaged matrix passes."),
    (3, 14): PackagingRuntime("3.14", "experimental", False, False, "Experimental — Not a validated MSAA release packaging runtime."),
}


def runtime_policy(version_info=None) -> PackagingRuntime:
    version_info = version_info or sys.version_info
    return RUNTIME_MATRIX.get((version_info.major, version_info.minor), PackagingRuntime(f"{version_info.major}.{version_info.minor}", "unsupported", False, False, "No MSAA packaging qualification exists for this runtime."))


def dependency_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "missing"


def constraint_hash(root: Path, policy: PackagingRuntime) -> str:
    path = root / "constraints" / f"macos-py{policy.python.replace('.', '')}.txt"
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"


def build_manifest(root: Path, policy: PackagingRuntime, *, build_id: str) -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True).stdout)
    except (OSError, subprocess.SubprocessError):
        commit, dirty = "unknown", True
    return {"schema_version":"1.0", "build_id":build_id, "build_timestamp":datetime.now(timezone.utc).isoformat(),
        "python_executable":sys.executable, "python_version":platform.python_version(), "architecture":platform.machine(),
        "platform":platform.platform(), "runtime_classification":policy.classification, "release_gate":policy.release_gate,
        "pyinstaller_version":dependency_version("PyInstaller"), "pyside6_version":dependency_version("PySide6"),
        "setuptools_version":dependency_version("setuptools"), "wheel_version":dependency_version("wheel"),
        "packaging_version":dependency_version("packaging"), "altgraph_version":dependency_version("altgraph"),
        "hooks_contrib_version":dependency_version("pyinstaller-hooks-contrib"), "constraints_sha256":constraint_hash(root, policy),
        "git_commit":commit, "source_tree_dirty":dirty, "spec_file":"Mac Audit Agent.spec"}


def preflight(root: Path, *, allow_experimental: bool) -> tuple[PackagingRuntime, list[str]]:
    policy = runtime_policy()
    failures: list[str] = []
    if not policy.packaging_allowed_by_default and not allow_experimental:
        failures.append(f"MSAA packaging is not validated for Python {platform.python_version()} in this release. Validated packaging runtime: Python 3.12.x. Detected runtime: Python {platform.python_version()}. Use the documented Python 3.12 build environment or pass --experimental-runtime for the compatibility job.")
    for package in ("PyInstaller", "PySide6", "pyinstaller-hooks-contrib", "altgraph", "setuptools", "wheel", "packaging"):
        if dependency_version(package) == "missing":
            failures.append(f"Required packaging dependency is missing: {package}. Interpreter: {sys.executable}. Install with: {sys.executable} -m pip install -r {root / 'requirements-build.txt'}")
    return policy, failures

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.runtime.packaging_compatibility import RUNTIME_MATRIX, build_manifest, runtime_policy


def test_runtime_policy_keeps_312_as_only_release_gate():
    assert runtime_policy(SimpleNamespace(major=3, minor=12)).release_gate
    assert runtime_policy(SimpleNamespace(major=3, minor=12)).packaging_allowed_by_default
    assert runtime_policy(SimpleNamespace(major=3, minor=13)).classification == "compatibility_candidate"
    assert runtime_policy(SimpleNamespace(major=3, minor=14)).classification == "experimental"
    assert not runtime_policy(SimpleNamespace(major=3, minor=14)).release_gate
    assert not runtime_policy(SimpleNamespace(major=3, minor=14)).packaging_allowed_by_default


def test_build_manifest_records_interpreter_toolchain_and_constraints():
    root = Path(__file__).resolve().parents[1]
    manifest = build_manifest(root, RUNTIME_MATRIX[(3, 12)], build_id="test-build")
    assert manifest["build_id"] == "test-build"
    assert manifest["python_executable"]
    assert manifest["python_version"]
    assert manifest["architecture"]
    assert manifest["git_commit"]
    assert manifest["constraints_sha256"] != "missing"
    assert manifest["spec_file"] == "Mac Audit Agent.spec"


def test_packaging_files_are_pinned_and_module_invocation_is_used():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements-build.txt").read_text()
    assert "PyInstaller==" in requirements and "PySide6==" in (root / "requirements-gui.txt").read_text()
    script = (root / "scripts/build_pyinstaller.py").read_text()
    assert 'sys.executable, "-m", "PyInstaller"' in script
    assert "--experimental-runtime" in script
    assert "anti_typosquatting/data_manifest.json" in script


def test_default_requirements_are_desktop_friendly_and_gui_is_runtime_guarded():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text()
    project = (root / "pyproject.toml").read_text()

    assert ".[compat,desktop,crypto,exports,network]" in requirements
    assert "requirements-core.txt" in requirements
    assert "tomli>=2.0,<3; python_version < '3.11'" in project
    assert "python_version >= '3.10' and python_version < '3.15'" in project


def test_pyinstaller_spec_bundles_runtime_json_resources():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "Mac Audit Agent.spec").read_text()

    assert "anti_typosquatting/*.json" in spec

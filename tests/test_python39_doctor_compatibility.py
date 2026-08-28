from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

from mac_audit_agent.runtime.startup_error_classifier import classify_startup_error


ROOT = Path(__file__).parents[1]
PYTHON39 = Path("/Library/Developer/CommandLineTools/usr/bin/python3")


def _python39(code: str) -> subprocess.CompletedProcess[str]:
    assert PYTHON39.is_file(), "Apple Command Line Tools Python 3.9 is required for this regression"
    return subprocess.run([str(PYTHON39), "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)


def test_python39_compat_modules_and_doctor_report_import() -> None:
    code = (
        "import json,sys; "
        "import mac_audit_agent.compat.python_features; import mac_audit_agent.compat.typing; "
        "from mac_audit_agent.runtime.doctor import build_doctor_report; r=build_doctor_report(); "
        "print(json.dumps({'python':r['python'],'gui':any(n.startswith('PySide6') for n in sys.modules)}))"
    )
    result = _python39(code)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.splitlines()[-1])
    assert payload["python"]["runtime_tier"] == "deprecated_doctor_only"
    assert payload["python"]["gui_runtime_allowed"] is False
    assert payload["python"]["headless_doctor_allowed"] is True
    assert payload["gui"] is False


def test_python39_doctor_guidance_does_not_recommend_stdlib_backports() -> None:
    result = _python39("from mac_audit_agent.runtime.doctor import build_doctor_report; print(build_doctor_report()['python']['recommended_python'])")
    assert result.returncode == 0, result.stderr
    guidance = (result.stdout + result.stderr).lower()
    assert "pip install typing" not in guidance
    assert "pip install enum" not in guidance


def test_typealias_gap_is_pycompat002() -> None:
    result = classify_startup_error(kind="import_error", details="ImportError: cannot import name 'TypeAlias' from 'typing'")
    assert result.error_code == "PYCOMPAT002"
    assert result.category == "python_typing_feature_gap"
    assert result.component == "typing.TypeAlias"
    assert "no pip package" in result.recommended_action.lower()


def test_advanced_typing_imports_are_centralized() -> None:
    advanced = {"TypeAlias", "Self", "Required", "NotRequired", "TypeGuard", "LiteralString", "TypeAliasType", "override"}
    violations = []
    package = ROOT / "mac_audit_agent"
    for path in package.rglob("*.py"):
        if path.parent == package / "compat":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "typing" and advanced.intersection(alias.name for alias in node.names):
                violations.append(str(path.relative_to(ROOT)))
    assert not violations

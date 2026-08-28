from __future__ import annotations

import ast
import importlib
from enum import auto
from pathlib import Path

from mac_audit_agent.compat.enum import StrEnum
from mac_audit_agent.runtime.startup import classify_import_failure


class _Example(StrEnum):
    EXPLICIT = "explicit"
    AUTOMATIC = auto()


def test_python310_strenum_behavior() -> None:
    assert isinstance(_Example.EXPLICIT, str)
    assert str(_Example.EXPLICIT) == "explicit"
    assert _Example.AUTOMATIC.value == "automatic"


def test_core_headless_packages_import() -> None:
    for module_name in (
        "mac_audit_agent.integrity",
        "mac_audit_agent.protection",
        "mac_audit_agent.runtime",
        "mac_audit_agent.quality",
    ):
        assert importlib.import_module(module_name) is not None


def test_no_direct_stdlib_strenum_use() -> None:
    package_root = Path(__file__).resolve().parents[1] / "mac_audit_agent"
    violations: list[str] = []
    compatibility_module = package_root / "compat" / "enum.py"

    for path in package_root.rglob("*.py"):
        if path == compatibility_module:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "enum":
                if any(alias.name == "StrEnum" for alias in node.names):
                    violations.append(str(path.relative_to(package_root.parent)))
            if isinstance(node, ast.Attribute) and node.attr == "StrEnum":
                if isinstance(node.value, ast.Name) and node.value.id == "enum":
                    violations.append(str(path.relative_to(package_root.parent)))

    assert violations == []


def test_stdlib_symbol_failure_is_not_classified_as_a_pip_dependency() -> None:
    result = classify_import_failure(
        ImportError("cannot import name 'StrEnum' from 'enum'", name="enum")
    )
    assert result[0] == "PYCOMPAT001"
    guidance = " ".join(result[3]).lower()
    assert "no pip package is required" in guidance
    assert ".[gui]" not in guidance
    assert "pip install enum" not in guidance


def test_sudo_gui_is_blocked_before_cli_or_gui_import(monkeypatch) -> None:
    from mac_audit_agent import bootstrap

    messages: list[str] = []
    monkeypatch.setattr(bootstrap, "is_root_user", lambda: True)
    monkeypatch.setattr(bootstrap, "write_failure_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(bootstrap, "_emit_failure", messages.append)

    assert bootstrap.main([]) == 2
    assert "Do not start the MSAA GUI with sudo" in messages[0]

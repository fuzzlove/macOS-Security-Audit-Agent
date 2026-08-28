from __future__ import annotations

import ast
import sys
from pathlib import Path

import launcher


def test_launcher_top_level_is_stdlib_only() -> None:
    path = Path(__file__).resolve().parents[1] / "launcher.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    assert not any(name.startswith(("mac_audit_agent", "PySide6", "AppKit", "Cocoa")) for name in imports)


def test_launcher_contains_preflight_before_app_import() -> None:
    source = (Path(__file__).resolve().parents[1] / "launcher.py").read_text(encoding="utf-8")
    assert source.index("evaluate_gui_preflight") < source.index("from mac_audit_agent.app import")


def test_launcher_preserves_virtual_environment_interpreter_path(tmp_path: Path) -> None:
    launcher_path = tmp_path / "launcher.py"
    launcher_path.touch()
    interpreter = tmp_path / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(sys.executable)

    candidates = launcher._candidate_paths("gui", launcher_path)

    assert str(interpreter) in candidates


def test_sudo_gui_handoff_does_not_resolve_virtualenv_python() -> None:
    source = (Path(__file__).resolve().parents[1] / "launcher.py").read_text(encoding="utf-8")

    assert "reexec_as_user(user, os.path.abspath(sys.executable)" in source
    assert "reexec_as_user(user, os.path.realpath(sys.executable)" not in source

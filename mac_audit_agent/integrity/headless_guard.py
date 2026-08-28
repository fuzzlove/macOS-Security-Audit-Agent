from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.headless_sentinel import snapshot_headless_imports

FORBIDDEN_GUI_MODULE_MARKERS = ("PySide6", "PyQt6", "PyQt5", "AppKit", "Cocoa", "objc")


class HeadlessIntegrityError(RuntimeError):
    pass


def ensure_integrity_cli_headless_safe(*, strict_loaded_modules: bool = True) -> None:
    if strict_loaded_modules:
        snapshot = snapshot_headless_imports()
        if not snapshot.headless_safe:
            raise HeadlessIntegrityError(f"HEADLESS_GUI_IMPORT: integrity CLI loaded GUI modules: {', '.join(snapshot.imported_gui_modules)}")
    offenders = []
    integrity_root = Path(__file__).resolve().parent
    for source_path in integrity_root.glob("*.py"):
        if source_path.name in {"headless_guard.py", "headless_sentinel.py"}:
            continue
        text = source_path.read_text(encoding="utf-8")
        for marker in FORBIDDEN_GUI_MODULE_MARKERS + ("QApplication",):
            if marker in text:
                offenders.append(f"{source_path.name}:{marker}")
    if offenders:
        raise HeadlessIntegrityError(f"integrity package references GUI modules: {', '.join(sorted(offenders))}")


__all__ = ["FORBIDDEN_GUI_MODULE_MARKERS", "HeadlessIntegrityError", "ensure_integrity_cli_headless_safe"]

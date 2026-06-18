from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from mac_audit_agent.ui.main_window import MainWindow, create_security_tray_icon
from mac_audit_agent.ui.startup_notice import preview_startup_notice


def default_gui_db_path() -> Path:
    return Path.home() / ".mac_audit_agent.sqlite3"


def fallback_gui_db_path() -> Path:
    return Path.home() / ".mac_audit_agent" / "audit.sqlite3"


def emergency_gui_db_path() -> Path:
    return Path(tempfile.gettempdir()) / f"mac_audit_agent_{Path.home().name}" / "audit.sqlite3"


def _is_writable_database_open_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and any(
        marker in message
        for marker in (
            "readonly database",
            "read-only database",
            "unable to open database",
            "permission denied",
        )
    )


def _open_main_window_with_writable_db(db_path: Path) -> MainWindow:
    attempted: list[tuple[Path, str]] = []
    candidates: list[Path] = []
    for candidate in [db_path, fallback_gui_db_path(), emergency_gui_db_path()]:
        if candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            window = MainWindow(candidate)
        except sqlite3.OperationalError as exc:
            if not _is_writable_database_open_error(exc):
                raise
            attempted.append((candidate, str(exc)))
            continue
        except OSError as exc:
            attempted.append((candidate, str(exc)))
            continue
        if attempted:
            details = "\n".join(f"- {path}: {error}" for path, error in attempted)
            QMessageBox.warning(
                window,
                "Database Is Not Writable",
                (
                    "MSAA could not open the normal database location for writing.\n\n"
                    f"{details}\n\n"
                    "MSAA started with this writable database instead:\n"
                    f"{candidate}\n\n"
                    "The original database files were left unchanged. Fix ownership or permissions if you want to use them again."
                ),
            )
        return window
    details = "\n".join(f"- {path}: {error}" for path, error in attempted)
    raise sqlite3.OperationalError(f"unable to open any writable MSAA database:\n{details}")


def main() -> int:
    app = QApplication(sys.argv)
    if hasattr(app, "setWindowIcon"):
        app.setWindowIcon(create_security_tray_icon())
    if not preview_startup_notice():
        return 0
    db_path = default_gui_db_path()
    window = _open_main_window_with_writable_db(db_path)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

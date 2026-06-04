from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.startup_notice import preview_startup_notice


def main() -> int:
    app = QApplication(sys.argv)
    if not preview_startup_notice():
        return 0
    db_path = Path.home() / ".mac_audit_agent.sqlite3"
    window = MainWindow(db_path)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

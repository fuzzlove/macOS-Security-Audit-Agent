from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from mac_audit_agent.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    db_path = Path.home() / ".mac_audit_agent.sqlite3"
    window = MainWindow(db_path)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())


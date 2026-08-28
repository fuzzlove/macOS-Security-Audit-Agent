"""Minimal isolated QApplication lifecycle probe; never imports the MSAA UI."""

from __future__ import annotations

import json
import sys

from .gui_preflight import evaluate_gui_preflight


def main()->int:
    preflight=evaluate_gui_preflight()
    if not preflight.allowed:
        print(json.dumps({"safe":False,"failure_code":preflight.failure_code,"message":preflight.message},sort_keys=True));return 2
    from .qapplication_guard import assert_qapplication_allowed
    assert_qapplication_allowed(preflight)
    from PySide6.QtWidgets import QApplication
    app=QApplication.instance() or QApplication(["msaa-isolated-qt-probe"]);app.processEvents();app.quit()
    print(json.dumps({"safe":True,"failure_code":"","platform_backend":preflight.test_backend or "cocoa"},sort_keys=True));return 0


if __name__=="__main__":raise SystemExit(main())

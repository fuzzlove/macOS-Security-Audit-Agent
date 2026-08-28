from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.apple_diagnostics.collection import capture_watermarked_screenshot
from mac_audit_agent.ui.apple_diagnostics_panel import AppleDiagnosticsPanel


def test_watermarked_screenshot_is_png_hashed_and_contains_red_pixels(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    source = QImage(640, 360, QImage.Format.Format_ARGB32)
    source.fill(QColor("white"))

    metadata = capture_watermarked_screenshot(
        tmp_path / "capture.png",
        case_id="INC-2026-001",
        source_image=source,
        captured_at="2026-08-25T12:00:00+00:00",
    )

    rendered = QImage(metadata["path"])
    red_pixels = 0
    for y in range(max(0, rendered.height() - 80), rendered.height(), 4):
        for x in range(0, rendered.width(), 4):
            color = rendered.pixelColor(x, y)
            if color.red() > color.green() * 1.5 and color.red() > color.blue() * 1.5:
                red_pixels += 1
    assert metadata["sha256"]
    assert metadata["watermark_color"] == "red"
    assert metadata["screen_scope"] == "provided_image"
    assert "INC-2026-001" in metadata["watermark"]
    assert red_pixels > 20
    app.processEvents()


def test_apple_diagnostics_section_exposes_capture_and_verification_controls() -> None:
    app = QApplication.instance() or QApplication([])
    panel = AppleDiagnosticsPanel(app_version="test")

    capture = panel.findChild(QPushButton, "captureAppleDiagnosticsEvidenceButton")
    verify = panel.findChild(QPushButton, "verifyAppleDiagnosticsEvidenceButton")

    assert capture is not None
    assert "Capture & Seal" in capture.text()
    assert verify is not None
    assert verify.isEnabled() is False
    assert "tamper-evident" in panel.findChild(type(panel.status), "appleDiagnosticsIntegrityQualification").text().lower()
    panel.close()
    app.processEvents()

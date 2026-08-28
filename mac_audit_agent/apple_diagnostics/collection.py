from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


APPLE_DIAGNOSTICS_SUPPORT_URL = "https://support.apple.com/102550"
MAX_DIAGNOSTIC_OUTPUT_BYTES = 2 * 1024 * 1024


def _run_bounded(command: list[str], runner: Callable[..., Any], *, timeout: int) -> dict[str, Any]:
    try:
        completed = runner(command, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = (getattr(completed, "stdout", "") or "").encode("utf-8", errors="replace")[:MAX_DIAGNOSTIC_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr = (getattr(completed, "stderr", "") or "").encode("utf-8", errors="replace")[:32768].decode("utf-8", errors="replace")
        return {
            "return_code": int(getattr(completed, "returncode", 1) or 0),
            "stdout": stdout,
            "stderr": stderr,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "truncated": len((getattr(completed, "stdout", "") or "").encode("utf-8", errors="replace")) > MAX_DIAGNOSTIC_OUTPUT_BYTES,
        }
    except Exception as exc:
        return {"return_code": None, "stdout": "", "stderr": "", "stdout_sha256": "", "truncated": False, "exception": f"{type(exc).__name__}: {exc}"}


def collect_apple_diagnostic_context(runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Collect bounded, read-only context useful beside an Apple Diagnostics run.

    This does not run or impersonate Apple's boot-time hardware diagnostic and
    cannot retrieve an Apple Diagnostics reference code. The user records that
    code separately after following Apple's documented workflow.
    """

    runner = runner or subprocess.run
    sw_vers = _run_bounded(["/usr/bin/sw_vers"], runner, timeout=8)
    profiler = _run_bounded(
        [
            "/usr/sbin/system_profiler",
            "SPHardwareDataType",
            "SPSoftwareDataType",
            "SPDiagnosticsDataType",
            "-json",
            "-detailLevel",
            "mini",
        ],
        runner,
        timeout=30,
    )
    profiler_payload: dict[str, Any] | str = profiler.get("stdout", "")
    if profiler.get("return_code") == 0 and profiler.get("stdout"):
        try:
            profiler_payload = json.loads(str(profiler["stdout"]))
        except json.JSONDecodeError:
            pass
    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collection_scope": "bounded_read_only_apple_diagnostics_context",
        "platform": platform.platform(),
        "macos_version": platform.mac_ver()[0],
        "machine_architecture": platform.machine(),
        "sw_vers": sw_vers,
        "system_profiler": {
            "return_code": profiler.get("return_code"),
            "stderr": profiler.get("stderr", ""),
            "stdout_sha256": profiler.get("stdout_sha256", ""),
            "truncated": profiler.get("truncated", False),
            "exception": profiler.get("exception", ""),
            "data": profiler_payload,
        },
        "apple_diagnostics_reference_code": "user_entry_required",
        "official_instructions": APPLE_DIAGNOSTICS_SUPPORT_URL,
        "limitations": [
            "This collection does not run Apple's boot-time Apple Diagnostics test.",
            "MSAA cannot retrieve or validate an Apple Diagnostics reference code automatically.",
            "Screen capture contents and diagnostic context must be privacy-reviewed before sharing.",
        ],
    }


def capture_watermarked_screenshot(
    destination: str | Path,
    *,
    case_id: str,
    source_image: Any | None = None,
    screen: Any | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Capture or render a red-watermarked PNG and return its integrity metadata."""

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPen
    from PySide6.QtWidgets import QApplication

    captured_from_screen = source_image is None
    if captured_from_screen:
        target_screen = screen or QApplication.primaryScreen()
        if target_screen is None:
            raise RuntimeError("No display is available for screenshot evidence collection.")
        source_image = target_screen.grabWindow(0).toImage()
    image = source_image.copy() if hasattr(source_image, "copy") else QImage(source_image)
    if image.isNull():
        raise RuntimeError("Screen capture failed. Grant Screen Recording access if macOS requests it, then retry.")

    captured_at = captured_at or datetime.now(timezone.utc).isoformat()
    safe_case_id = "".join(character for character in str(case_id) if character.isalnum() or character in "-_.")[:80] or "UNASSIGNED"
    watermark = f"MSAA APPLE DIAGNOSTICS EVIDENCE  •  CASE {safe_case_id}  •  {captured_at}"
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    banner_height = max(58, min(110, image.height() // 7))
    painter.fillRect(0, image.height() - banner_height, image.width(), banner_height, QColor(150, 0, 0, 205))
    font = QFont("Helvetica", max(12, min(30, image.width() // 38)))
    font.setBold(True)
    painter.setFont(font)
    painter.setPen(QPen(QColor(255, 255, 255)))
    painter.drawText(18, image.height() - banner_height, max(1, image.width() - 36), banner_height, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), watermark)
    painter.setPen(QPen(QColor(220, 0, 0, 170)))
    diagonal_font = QFont("Helvetica", max(20, min(70, image.width() // 16)))
    diagonal_font.setBold(True)
    painter.setFont(diagonal_font)
    painter.translate(image.width() / 2, image.height() / 2)
    painter.rotate(-24)
    painter.drawText(-image.width() // 3, -20, "TAMPER-EVIDENT CAPTURE")
    painter.end()

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not image.save(str(path), "PNG"):
        raise OSError(f"Could not write screenshot evidence to {path}")
    path.chmod(0o400)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path),
        "sha256": digest,
        "algorithm": "SHA-256",
        "captured_at": captured_at,
        "case_id": safe_case_id,
        "watermark": watermark,
        "watermark_color": "red",
        "width": image.width(),
        "height": image.height(),
        "screen_scope": "primary_display" if captured_from_screen else "provided_image",
        "integrity_model": "tamper-evident hash and visible watermark; not immutable",
    }


__all__ = [
    "APPLE_DIAGNOSTICS_SUPPORT_URL",
    "capture_watermarked_screenshot",
    "collect_apple_diagnostic_context",
]

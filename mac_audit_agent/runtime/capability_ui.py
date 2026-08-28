from __future__ import annotations

from typing import Any


def apply_capability_to_control(control: Any, capability: Any) -> bool:
    """Apply a capability result to a Qt-like control without importing Qt.

    This deliberately uses the small QWidget protocol (``setEnabled`` and
    ``setToolTip``), keeping the runtime capability layer usable by headless
    commands and tests.
    """

    available = getattr(capability, "status", "unavailable") in {"available", "degraded"}
    control.setEnabled(bool(available))
    message = str(getattr(capability, "user_message", "") or "")
    if available and not message:
        message = f"{getattr(capability, 'display_name', 'This capability')} is available."
    elif not message:
        message = "This action is unavailable in the current runtime."
    control.setToolTip(message)
    return bool(available)


__all__ = ["apply_capability_to_control"]

from __future__ import annotations

from dataclasses import dataclass, field

from PySide6.QtWidgets import QWidget


@dataclass(frozen=True)
class ActionState:
    enabled: bool
    visible: bool = True
    reason: str = ""
    requirements: list[str] = field(default_factory=list)


def apply_action_state(widget: QWidget, state: ActionState) -> None:
    if hasattr(widget, "setVisible"):
        widget.setVisible(state.visible)
    widget.setEnabled(state.enabled)
    if state.enabled:
        tooltip = (widget.toolTip() or "") if hasattr(widget, "toolTip") else ""
    else:
        requirement_text = ", ".join(state.requirements)
        tooltip = state.reason or (f"Requires: {requirement_text}" if requirement_text else "Unavailable in the current state.")
    if hasattr(widget, "setToolTip"):
        widget.setToolTip(tooltip)

"""Read-only product preview boundary for unlicensed MSAA installations."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QEvent, QObject, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractSpinBox,
    QComboBox,
    QLineEdit,
    QPlainTextEdit,
    QStackedWidget,
    QTextEdit,
    QWidget,
)

from mac_audit_agent.licensing.manager import LicenseManager

_PREVIEW_WORDS = frozenset(
    {
        "about",
        "back",
        "close",
        "collapse",
        "copy",
        "details",
        "documentation",
        "exit",
        "expand",
        "explain",
        "guide",
        "help",
        "learn",
        "next",
        "open",
        "presentation",
        "preview",
        "previous",
        "quit",
        "show",
        "slide",
        "view",
        "why",
    }
)


def preview_control_allowed(text: str, object_name: str = "", *, checkable: bool = False) -> bool:
    """Return whether a control is passive navigation or explanatory UI."""
    if checkable:
        return False
    normalized = " ".join(str(text or "").replace("&", "").casefold().split())
    identifier = str(object_name or "").casefold()
    words = set(normalized.replace("…", "").split())
    if words & _PREVIEW_WORDS:
        return True
    return any(token in identifier for token in ("help", "detail", "preview", "next", "previous", "expand", "collapse"))


def _has_allowed_ancestor(widget: QWidget) -> bool:
    current: QWidget | None = widget
    while current is not None:
        if bool(current.property("demoAllowed")):
            return True
        name = current.objectName().casefold()
        if name.startswith("support"):
            return True
        current = current.parentWidget()
    return False


class DemoPreviewController(QObject):
    """Locks operational GUI controls while preserving browsable content."""

    def __init__(
        self,
        *,
        window: QWidget,
        pages: QStackedWidget,
        banner: QWidget,
        banner_message: Callable[[str], None],
        manager_factory: Callable[[], LicenseManager] = LicenseManager,
    ) -> None:
        super().__init__(window)
        self.window = window
        self.pages = pages
        self.banner = banner
        self.banner_message = banner_message
        self.manager_factory = manager_factory
        self.demo_mode = True
        self._boundary_update_pending = False
        pages.installEventFilter(self)
        pages.currentChanged.connect(lambda _index: QTimer.singleShot(0, self.refresh))

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in {QEvent.Type.ChildAdded, QEvent.Type.EnabledChange}:
            self._schedule_boundary_update()
        return False

    def _schedule_boundary_update(self) -> None:
        if self._boundary_update_pending:
            return
        self._boundary_update_pending = True
        QTimer.singleShot(0, self._run_scheduled_boundary_update)

    def _run_scheduled_boundary_update(self) -> None:
        self._boundary_update_pending = False
        self._apply_widget_boundary()
        self._apply_action_boundary()

    def refresh(self) -> dict[str, object]:
        manager = self.manager_factory()
        status = manager.status()
        access = manager.product_access(status)
        self.demo_mode = not bool(access["operator_actions_enabled"])
        self.pages.setProperty("demoPreviewMode", self.demo_mode)
        self.banner.setVisible(self.demo_mode)
        self.banner_message(str(access["reason"]))
        self._apply_widget_boundary()
        self._apply_action_boundary()
        return access

    def _apply_widget_boundary(self) -> None:
        for widget in self.pages.findChildren(QWidget):
            widget.installEventFilter(self)
        controls: list[QWidget] = []
        controls.extend(self.pages.findChildren(QAbstractButton))
        controls.extend(self.pages.findChildren(QComboBox))
        controls.extend(self.pages.findChildren(QAbstractSpinBox))
        controls.extend(widget for widget in self.pages.findChildren(QLineEdit) if not widget.isReadOnly())
        controls.extend(widget for widget in self.pages.findChildren(QTextEdit) if not widget.isReadOnly())
        controls.extend(widget for widget in self.pages.findChildren(QPlainTextEdit) if not widget.isReadOnly())
        for control in controls:
            control.installEventFilter(self)
            if _has_allowed_ancestor(control):
                self._restore(control)
                continue
            allowed = isinstance(control, QAbstractButton) and preview_control_allowed(
                control.text(), control.objectName(), checkable=control.isCheckable()
            )
            if self.demo_mode and not allowed:
                self._lock(control)
            else:
                self._restore(control)

    def _apply_action_boundary(self) -> None:
        for action in self.window.findChildren(QAction):
            action.installEventFilter(self)
            if action.menu() is not None:
                continue
            allowed = preview_control_allowed(action.text(), action.objectName(), checkable=action.isCheckable())
            if self.demo_mode and not allowed:
                self._lock(action)
            else:
                self._restore(action)

    @staticmethod
    def _lock(control: QWidget | QAction) -> None:
        if control.isEnabled():
            first_lock = not bool(control.property("demoLockedByLicense"))
            control.setProperty("demoLockedByLicense", True)
            control.setEnabled(False)
            if isinstance(control, QWidget) and first_lock:
                existing = control.toolTip().strip()
                note = "Demo Preview: purchase or import a signed MSAA license to enable this operational control."
                control.setProperty("demoOriginalToolTip", existing)
                control.setToolTip(f"{existing}\n\n{note}".strip())

    @staticmethod
    def _restore(control: QWidget | QAction) -> None:
        if not bool(control.property("demoLockedByLicense")):
            return
        control.setProperty("demoLockedByLicense", False)
        control.setEnabled(True)
        if isinstance(control, QWidget):
            control.setToolTip(str(control.property("demoOriginalToolTip") or ""))


__all__ = ["DemoPreviewController", "preview_control_allowed"]

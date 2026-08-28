from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any


@dataclass(frozen=True)
class ButtonLayoutIssue:
    object_name: str
    text: str
    parent: str
    geometry: str
    issue: str
    severity: str
    recommended_fix: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def audit_buttons(root_widget: Any) -> list[dict[str, Any]]:
    from PySide6.QtCore import QRect
    from PySide6.QtWidgets import QAbstractButton

    records: list[dict[str, Any]] = []
    buttons = [button for button in root_widget.findChildren(QAbstractButton) if button.isVisible() and not _is_qt_internal_button(button)]
    for button in buttons:
        parent = button.parentWidget()
        geom = button.geometry()
        hint = button.sizeHint()
        issues: list[ButtonLayoutIssue] = []
        name = button.objectName() or button.text() or type(button).__name__
        text = button.text()
        parent_name = parent.objectName() if parent is not None and parent.objectName() else type(parent).__name__ if parent is not None else ""
        if geom.height() and geom.height() < min(hint.height(), 26):
            issues.append(_issue(name, text, parent_name, geom, "button text may be vertically clipped", "HIGH", "Use canonical compact/normal button height."))
        if geom.width() and geom.width() < min(hint.width(), 34) and text:
            issues.append(_issue(name, text, parent_name, geom, "button text may be horizontally clipped", "HIGH", "Shorten text, add tooltip, or allow action row wrapping."))
        if parent is not None and not QRect(0, 0, parent.width(), parent.height()).contains(geom):
            issues.append(_issue(name, text, parent_name, geom, "button outside parent bounds", "BLOCKER", "Use responsive layout or scroll area."))
        if button.maximumHeight() == button.minimumHeight() and button.minimumHeight() > 38 and button.property("fixedSizeAllowed") is not True:
            issues.append(_issue(name, text, parent_name, geom, "unsafe fixed/tall button height", "MEDIUM", "Use canonical button size class instead of fixed height."))
        if not text and not button.toolTip():
            issues.append(_issue(name, text, parent_name, geom, "icon-only button lacks tooltip", "HIGH", "Add tooltip and accessible name."))
        if len(text) > 28 and not button.toolTip():
            issues.append(_issue(name, text, parent_name, geom, "long button text lacks tooltip fallback", "MEDIUM", "Shorten text and move detail to tooltip."))
        records.append(
            {
                "objectName": name,
                "text": text,
                "parent": parent_name,
                "geometry": _rect_text(geom),
                "size_hint": f"{hint.width()}x{hint.height()}",
                "tooltip_exists": bool(button.toolTip()),
                "accessible_name": button.accessibleName(),
                "issue_count": len(issues),
                "issues": [issue.to_dict() for issue in issues],
                "status": "PASS" if not issues else max((issue.severity for issue in issues), key=_severity_rank),
            }
        )
    _add_overlap_issues(buttons, records)
    return records


def static_button_source_audit(paths: list[Path] | None = None) -> list[dict[str, Any]]:
    paths = paths or sorted(Path("mac_audit_agent/ui").glob("*.py"))
    records: list[dict[str, Any]] = []
    button_pattern = re.compile(r"(?P<name>self\.\w+|\w+)\s*=\s*(?P<type>QPushButton|QToolButton|QCommandLinkButton)\((?P<label>[^)]*)\)")
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in button_pattern.finditer(text):
            name = match.group("name").replace("self.", "")
            label = match.group("label").strip().strip("\"'")
            local_window = text[match.start() : match.start() + 1200]
            fixed = any(token in local_window for token in [".setFixedSize", ".setFixedHeight", ".setFixedWidth"])
            tooltip = f"{name}.setToolTip" in text or ".setToolTip" in local_window
            connected = f"{name}.clicked.connect" in text or ".clicked.connect" in local_window
            issue = ""
            severity = "PASS"
            if fixed:
                issue = "fixed size usage requires review"
                severity = "WARN"
            if len(label) > 28 and not tooltip:
                issue = "long label without tooltip"
                severity = "FAIL"
            records.append(
                {
                    "file": str(path),
                    "objectName": name,
                    "text": label,
                    "type": match.group("type"),
                    "fixed_size_usage": fixed,
                    "tooltip_exists": tooltip,
                    "callback_connected": connected,
                    "issue": issue,
                    "status": severity,
                }
            )
    return records


def write_button_layout_audit(records: list[dict[str, Any]], path: Path | None = None) -> Path:
    path = path or Path("reports") / "pre_uat" / "ui_audits" / "PRE_UAT_BUTTON_LAYOUT_AUDIT.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Pre-UAT Button Layout Audit",
        "",
        "| Status | Button | Text | Parent/File | Geometry | Issues |",
        "|---|---|---|---|---|---|",
    ]
    for record in records:
        issues = record.get("issues", record.get("issue", ""))
        if isinstance(issues, list):
            issue_text = "; ".join(item.get("issue", "") for item in issues) or "none"
        else:
            issue_text = str(issues or "none")
        parent = record.get("parent") or record.get("file", "")
        lines.append(
            f"| {record.get('status', '')} | {str(record.get('objectName', '')).replace('|', '/')} | "
            f"{str(record.get('text', '')).replace('|', '/')} | {str(parent).replace('|', '/')} | "
            f"{record.get('geometry', '')} | {issue_text.replace('|', '/')} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _add_overlap_issues(buttons: list[Any], records: list[dict[str, Any]]) -> None:
    by_name = {record["objectName"]: record for record in records}
    for index, left in enumerate(buttons):
        for right in buttons[index + 1 :]:
            if left.parentWidget() is not right.parentWidget():
                continue
            if left.geometry().intersects(right.geometry()) and left.geometry() != right.geometry():
                for button in [left, right]:
                    name = button.objectName() or button.text() or type(button).__name__
                    record = by_name.get(name)
                    if record is None:
                        continue
                    issue = _issue(name, button.text(), type(button.parentWidget()).__name__, button.geometry(), "button overlaps sibling", "BLOCKER", "Use ResponsiveActionRow or adjust parent layout spacing.")
                    record.setdefault("issues", []).append(issue.to_dict())
                    record["issue_count"] = len(record["issues"])
                    record["status"] = "BLOCKER"


def _is_qt_internal_button(button: Any) -> bool:
    name = button.objectName()
    parent = button.parentWidget()
    parent_name = parent.objectName() if parent is not None else ""
    return name in {"ScrollLeftButton", "ScrollRightButton"} and parent_name == "qt_tabwidget_tabbar"


def _issue(name: str, text: str, parent: str, geom: Any, issue: str, severity: str, fix: str) -> ButtonLayoutIssue:
    return ButtonLayoutIssue(name, text, parent, _rect_text(geom), issue, severity, fix)


def _rect_text(rect: Any) -> str:
    return f"{rect.x()},{rect.y()} {rect.width()}x{rect.height()}"


def _severity_rank(value: str) -> int:
    return {"PASS": 0, "WARN": 1, "MEDIUM": 2, "HIGH": 3, "FAIL": 3, "BLOCKER": 4}.get(value, 0)


__all__ = ["audit_buttons", "static_button_source_audit", "write_button_layout_audit", "ButtonLayoutIssue"]

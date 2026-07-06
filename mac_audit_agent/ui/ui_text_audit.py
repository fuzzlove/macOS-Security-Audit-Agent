from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QLabel, QPushButton, QStackedWidget, QTabWidget, QWidget


IGNORED_TEXTS = {"?", "", "info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class DuplicateHeaderFinding:
    text: str
    widget_path: str
    parent_container: str
    recommended_fix: str

    def to_dict(self) -> dict[str, str]:
        return {
            "text": self.text,
            "widget_path": self.widget_path,
            "parent_container": self.parent_container,
            "recommended_fix": self.recommended_fix,
        }


def audit_visible_duplicate_headers(root_widget: QWidget) -> list[DuplicateHeaderFinding]:
    """Detect visible adjacent duplicate labels and repeated primary headers."""

    findings: list[DuplicateHeaderFinding] = []
    labels = [
        label
        for label in root_widget.findChildren(QLabel)
        if _is_visible_text_label(label)
    ]
    previous_by_parent: dict[QWidget, QLabel] = {}
    for label in labels:
        parent = label.parentWidget()
        text = _normalized_text(label.text())
        if not parent or text.lower() in IGNORED_TEXTS:
            continue
        previous = previous_by_parent.get(parent)
        if previous is not None and _normalized_text(previous.text()) == text:
            findings.append(
                DuplicateHeaderFinding(
                    text=text,
                    widget_path=_widget_path(label),
                    parent_container=_widget_path(parent),
                    recommended_fix="Remove one adjacent label or rename the second label to a specific section name.",
                )
            )
        previous_by_parent[parent] = label

    for page in _stack_pages(root_widget):
        page_headers = [
            header
            for header in page.findChildren(QWidget)
            if header.objectName() == "primaryPageHeader" and not header.isHidden()
        ]
        title_counts: dict[str, int] = {}
        for header in page_headers:
            title = str(header.property("pageHeaderTitle") or "").strip()
            if title:
                title_counts[title] = title_counts.get(title, 0) + 1
        for title, count in title_counts.items():
            if count > 1:
                findings.append(
                    DuplicateHeaderFinding(
                        text=title,
                        widget_path=_widget_path(page),
                        parent_container=_widget_path(root_widget),
                        recommended_fix="Keep one PageHeader per view and convert duplicates to SectionHeader widgets.",
                    )
                )
    return findings


def _stack_pages(root_widget: QWidget) -> list[QWidget]:
    pages: list[QWidget] = []
    for stack in root_widget.findChildren(QStackedWidget):
        for index in range(stack.count()):
            page = stack.widget(index)
            if page is not None:
                pages.append(page)
    for tabs in root_widget.findChildren(QTabWidget):
        for index in range(tabs.count()):
            page = tabs.widget(index)
            if page is not None:
                pages.append(page)
    if not pages:
        pages.append(root_widget)
    return pages


def _is_visible_text_label(label: QLabel) -> bool:
    if label.isHidden():
        return False
    text = _normalized_text(label.text())
    if not text or text.lower() in IGNORED_TEXTS:
        return False
    if isinstance(label.parentWidget(), QPushButton):
        return False
    return True


def _normalized_text(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("<"):
        return ""
    return " ".join(stripped.split())


def _widget_path(widget: QWidget) -> str:
    parts: list[str] = []
    current: QWidget | None = widget
    while current is not None:
        name = current.objectName() or current.__class__.__name__
        parts.append(name)
        current = current.parentWidget()
    return " > ".join(reversed(parts))

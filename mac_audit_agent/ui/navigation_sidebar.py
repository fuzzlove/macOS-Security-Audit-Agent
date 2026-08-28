from __future__ import annotations

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import QFont, QPainter, QPalette
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem


NAVIGATION_SECTION_ROLE = int(Qt.ItemDataRole.UserRole) + 41
NAVIGATION_SECTION_START_ROLE = int(Qt.ItemDataRole.UserRole) + 42


class GroupedNavigationDelegate(QStyledItemDelegate):
    """Paint compact navigation rows with lightweight section headings."""

    row_height = 30
    section_height = 19

    def sizeHint(self, option: QStyleOptionViewItem, index) -> QSize:  # noqa: N802 - Qt API
        height = self.row_height
        if bool(index.data(NAVIGATION_SECTION_START_ROLE)):
            height += self.section_height
        return QSize(max(option.rect.width(), 180), height)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        is_section_start = bool(index.data(NAVIGATION_SECTION_START_ROLE))
        item_option = QStyleOptionViewItem(option)
        if is_section_start:
            section = str(index.data(NAVIGATION_SECTION_ROLE) or "")
            painter.save()
            section_font = QFont(option.font)
            section_font.setPointSizeF(max(9.0, option.font.pointSizeF() - 1.0))
            section_font.setWeight(QFont.Weight.DemiBold)
            section_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.8)
            painter.setFont(section_font)
            color = option.palette.color(QPalette.ColorRole.PlaceholderText)
            painter.setPen(color)
            heading_rect = QRect(
                option.rect.x() + 10,
                option.rect.y() + 1,
                max(0, option.rect.width() - 20),
                self.section_height - 2,
            )
            painter.drawText(heading_rect, int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), section.upper())
            painter.restore()
            item_option.rect = QRect(
                option.rect.x(),
                option.rect.y() + self.section_height,
                option.rect.width(),
                option.rect.height() - self.section_height,
            )
        super().paint(painter, item_option, index)


__all__ = [
    "GroupedNavigationDelegate",
    "NAVIGATION_SECTION_ROLE",
    "NAVIGATION_SECTION_START_ROLE",
]

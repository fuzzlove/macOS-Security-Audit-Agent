from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QIcon

from mac_audit_agent.not_signed.models import InstalledSoftwareItem
from mac_audit_agent.ui.severity_styles import get_severity_style, normalize_severity


class SoftwareTableModel(QAbstractTableModel):
    COLUMNS = ("Severity / Impact", "Name", "Signature", "Developer", "Source", "Running", "Persistent", "Location")
    SORT_ROLE = Qt.UserRole + 1
    IMPACT_LABELS = {
        "critical": "Severe",
        "high": "Serious",
        "medium": "Material",
        "low": "Limited",
        "info": "Context",
        "none": "None",
        "unknown": "Unknown",
    }
    def __init__(self, parent=None): super().__init__(parent); self.items: list[InstalledSoftwareItem] = []
    def rowCount(self, parent=QModelIndex()): return 0 if parent.isValid() else len(self.items)
    def columnCount(self, parent=QModelIndex()): return len(self.COLUMNS)
    def headerData(self, section, orientation, role=Qt.DisplayRole): return self.COLUMNS[section] if role == Qt.DisplayRole and orientation == Qt.Horizontal else None
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.items): return None
        item = self.items[index.row()]
        if role == Qt.UserRole: return item
        severity = normalize_severity(item.severity)
        severity_style = get_severity_style(severity)
        impact = self.IMPACT_LABELS.get(severity, "Unknown")
        if role == self.SORT_ROLE:
            if index.column() == 0: return severity_style.sort_rank
            displayed = self.data(index, Qt.DisplayRole)
            return str(displayed or "").casefold()
        if role == Qt.DecorationRole and index.column() == 1 and item.icon_path:
            icon = QIcon(str(item.icon_path))
            return icon if not icon.isNull() else None
        if role == Qt.AccessibleTextRole: return f"{item.display_name}, {item.severity}, {item.signing.classification.value}"
        if role == Qt.ToolTipRole:
            reasons = "\n".join(item.risk_reasons) or "No elevated review factors were recorded."
            return f"{severity_style.label} severity — {impact.lower()} potential impact. {severity_style.description}\n{reasons}\nSeverity is a review priority, not proof of malware."
        if index.column() == 0 and role == Qt.BackgroundRole:
            return QBrush(QColor(severity_style.background))
        if index.column() == 0 and role == Qt.ForegroundRole:
            return QBrush(QColor(severity_style.foreground))
        if index.column() == 0 and role == Qt.FontRole:
            font = QFont(); font.setBold(True); return font
        if index.column() == 0 and role == Qt.TextAlignmentRole:
            return Qt.AlignCenter
        if role != Qt.DisplayRole: return None
        developer = item.signing.authorities[0] if item.signing.authorities else (item.signing.team_identifier or "Unknown")
        values = (f"{severity_style.label} · {impact}", item.display_name, item.signing.classification.value.replace("_", " ").title(), developer, item.source.title(), str(len(item.running_processes)), "Yes" if item.persistence_items else "No", str(item.bundle_path or item.executable_path))
        return values[index.column()]
    def add_item(self, item):
        self.beginInsertRows(QModelIndex(), len(self.items), len(self.items)); self.items.append(item); self.endInsertRows()
    def clear(self):
        self.beginResetModel(); self.items.clear(); self.endResetModel()

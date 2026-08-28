from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QAction, QIcon, QPixmap
from PySide6.QtWidgets import QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from mac_audit_agent.user_profiles import ROLE_PERMISSIONS, current_profile, profile_root, save_profile_metadata


class ProfileQuickSwitcher(QPushButton):
    """Compact sidebar identity control for profile access and macOS user switching."""

    open_profile_requested = Signal()
    switch_user_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("profileQuickSwitcher")
        self.setProperty("navigationRole", "utility")
        self.setProperty("utilityPlacement", "bottom_left")
        self.setMinimumHeight(58)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            "QPushButton#profileQuickSwitcher {"
            "text-align: left; padding: 7px 10px; border: 1px solid palette(mid); border-radius: 10px;"
            "}"
            "QPushButton#profileQuickSwitcher:hover { background: palette(alternate-base); }"
        )
        self.clicked.connect(self._show_menu)
        self.refresh()

    def refresh(self, _profile: dict | None = None) -> None:
        profile = current_profile()
        self.setText(f"  {profile.display_name}\n  @{profile.username} · {profile.role.value.title()}")
        self.setAccessibleName(f"Profile and user switching for {profile.display_name}, username {profile.username}")
        self.setToolTip("Open Identity & Access or switch to another macOS user.")
        pixmap = QPixmap(profile.avatar_path) if profile.avatar_path else QPixmap()
        if not pixmap.isNull():
            self.setIcon(QIcon(pixmap))
        else:
            self.setIcon(_initial_avatar(profile.display_name))
        self.setIconSize(QSize(40, 40))

    def _show_menu(self) -> None:
        menu = QMenu(self)
        profile_action = QAction("Open Identity & Access", menu)
        profile_action.triggered.connect(self.open_profile_requested)
        menu.addAction(profile_action)
        menu.addSeparator()
        switch_action = QAction("Switch macOS User…", menu)
        switch_action.setToolTip("Return to the macOS login window without signing out.")
        switch_action.triggered.connect(self.switch_user_requested)
        menu.addAction(switch_action)
        menu.exec(self.mapToGlobal(self.rect().topLeft()))


def _initial_avatar(display_name: str):
    from PySide6.QtGui import QColor, QFont, QIcon, QPainter

    pixmap = QPixmap(40, 40)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor("#2677a8"))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(0, 0, 40, 40)
    painter.setPen(QColor("#ffffff"))
    font = QFont()
    font.setBold(True)
    font.setPointSize(16)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignCenter, display_name[:1].upper() or "?")
    painter.end()
    return QIcon(pixmap)


class ProfileSettingsPanel(QWidget):
    profile_changed = Signal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent); self._avatar_path = ""; self._build(); self.refresh()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        intro = QLabel("Profiles are tied to macOS user accounts. Display names and avatars are personal preferences; permission roles cannot be self-elevated here.")
        intro.setWordWrap(True); layout.addWidget(intro)
        row = QHBoxLayout(); self.avatar = QLabel("No avatar"); self.avatar.setFixedSize(112, 112)
        self.avatar.setAlignment(Qt.AlignCenter); self.avatar.setStyleSheet("border: 1px solid palette(mid); border-radius: 12px;")
        row.addWidget(self.avatar)
        form = QFormLayout(); form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow); self.display_name = QLineEdit(); self.account = QLabel(); self.role = QLabel(); self.role_source = QLabel()
        self.permissions = QWidget(); self.permissions.setAccessibleName("Complete list of allowed actions"); self.permissions.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.MinimumExpanding); self.permissions_layout = QVBoxLayout(self.permissions); self.permissions_layout.setContentsMargins(0,0,0,0); self.permissions_layout.setSpacing(4)
        form.addRow("Display name", self.display_name); form.addRow("macOS account", self.account); form.addRow("Permission level", self.role)
        form.addRow("Role source", self.role_source); form.addRow("Allowed actions", self.permissions); row.addLayout(form, 1); layout.addLayout(row)
        actions = QHBoxLayout(); choose = QPushButton("Choose Avatar…"); remove = QPushButton("Remove Avatar"); save = QPushButton("Save Profile"); save.setProperty("role", "primary")
        choose.clicked.connect(self.choose_avatar); remove.clicked.connect(self.remove_avatar); save.clicked.connect(self.save)
        actions.addWidget(choose); actions.addWidget(remove); actions.addStretch(1); actions.addWidget(save); layout.addLayout(actions); layout.addStretch(1)

    def refresh(self) -> None:
        profile = current_profile(); self._avatar_path = profile.avatar_path; self.display_name.setText(profile.display_name)
        self.account.setText(f"{profile.username} (UID {profile.uid})"); self.role.setText(profile.role.value.replace("_", " ").title()); self.role_source.setText(profile.role_source)
        while self.permissions_layout.count():
            child=self.permissions_layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()
        for permission in sorted(ROLE_PERMISSIONS[profile.role]):
            action=QLabel(f"• {permission.replace('_', ' ').title()}"); action.setWordWrap(True); action.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Preferred); action.setAccessibleName(f"Allowed action: {permission.replace('_', ' ')}"); self.permissions_layout.addWidget(action)
        pixmap = QPixmap(profile.avatar_path) if profile.avatar_path else QPixmap()
        if not pixmap.isNull(): self.avatar.setPixmap(pixmap.scaled(104, 104, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else: self.avatar.setPixmap(QPixmap()); self.avatar.setText(profile.display_name[:1].upper() or "?")

    def choose_avatar(self) -> None:
        source, _ = QFileDialog.getOpenFileName(self, "Choose Profile Avatar", str(Path.home()), "Images (*.png *.jpg *.jpeg *.webp)")
        if not source: return
        root = profile_root(); root.mkdir(parents=True, exist_ok=True); root.chmod(0o700)
        destination = root / ("avatar" + Path(source).suffix.lower()); shutil.copy2(source, destination); destination.chmod(0o600)
        self._avatar_path = str(destination); self.refresh_avatar_preview()

    def refresh_avatar_preview(self) -> None:
        pixmap = QPixmap(self._avatar_path)
        if not pixmap.isNull(): self.avatar.setText(""); self.avatar.setPixmap(pixmap.scaled(104, 104, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def remove_avatar(self) -> None:
        self._avatar_path = ""; self.avatar.setPixmap(QPixmap()); self.avatar.setText(self.display_name.text()[:1].upper() or "?")

    def save(self) -> None:
        try:
            profile = save_profile_metadata(display_name=self.display_name.text(), avatar_path=self._avatar_path)
            self.refresh(); self.profile_changed.emit(profile.to_dict()); QMessageBox.information(self, "Profile Saved", "Your local profile preferences were saved.")
        except Exception as exc: QMessageBox.warning(self, "Profile Save Failed", str(exc))

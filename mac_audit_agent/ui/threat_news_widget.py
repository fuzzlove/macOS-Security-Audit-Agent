from __future__ import annotations

import logging
from datetime import datetime, timezone

from PySide6.QtCore import QObject, QSettings, QThread, QTimer, Qt, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from mac_audit_agent.news.models import NewsFilterMode, NewsSettings
from mac_audit_agent.news.navigation import NewsNavigator
from mac_audit_agent.news.repository import NewsRepository
from mac_audit_agent.news.security import normalize_article_url
from mac_audit_agent.news.service import NewsRefreshCoordinator
from mac_audit_agent.storage import AuditDatabase

LOGGER = logging.getLogger(__name__)


class _RefreshWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, coordinator: NewsRefreshCoordinator, protected_article_id: str | None) -> None:
        super().__init__(); self.coordinator = coordinator; self.protected_article_id = protected_article_id

    @Slot()
    def run(self) -> None:
        try: self.completed.emit(self.coordinator.refresh(self.protected_article_id))
        except Exception: self.failed.emit("MSAA could not retrieve The Hacker News feed. Check the network connection or try again later.")


class ThreatNewsWidget(QGroupBox):
    def __init__(self, database: AuditDatabase, parent: QWidget | None = None) -> None:
        super().__init__("Current Malware & Threat News", parent)
        self.setObjectName("currentMalwareThreatNews")
        self.preferences = QSettings("MSAA", "ThreatNews")
        self.repository = NewsRepository(database)
        self.navigator = NewsNavigator()
        self._thread: QThread | None = None
        self._worker: _RefreshWorker | None = None
        self._offline = False
        self._shutting_down = False
        self._build_ui()
        self._reload_settings()
        self._load_cache(preserve=False)
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(lambda: self.refresh_feed(manual=False))
        self._apply_auto_timer()

    @staticmethod
    def _boolean(value, default: bool) -> bool:
        if value is None: return default
        if isinstance(value, bool): return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        settings_row = QHBoxLayout()
        self.external_enabled = QCheckBox("Enable external cybersecurity news")
        self.auto_refresh = QCheckBox("Refresh news automatically")
        self.auto_advance = QCheckBox("Auto-advance latest story after refresh")
        self.filter_mode = QComboBox(); self.filter_mode.addItems([mode.value for mode in NewsFilterMode])
        settings_row.addWidget(self.external_enabled); settings_row.addWidget(self.auto_refresh)
        settings_row.addWidget(QLabel("View:")); settings_row.addWidget(self.filter_mode); settings_row.addStretch()
        layout.addLayout(settings_row)
        layout.addWidget(self.auto_advance)
        privacy = QLabel("When enabled, MSAA contacts only the configured The Hacker News RSS endpoint. Stories are cached locally; MSAA does not send reading telemetry or claim to verify publisher reporting.")
        privacy.setWordWrap(True); layout.addWidget(privacy)
        card = QGroupBox(); form = QFormLayout(card)
        self.title_label = QLabel(); self.title_label.setWordWrap(True); self.title_label.setStyleSheet("font-size: 16px; font-weight: 700;")
        self.published_label = QLabel(); self.categories_label = QLabel(); self.author_label = QLabel()
        self.summary_label = QLabel(); self.summary_label.setWordWrap(True); self.summary_label.setTextFormat(Qt.PlainText)
        self.source_label = QLabel("The Hacker News")
        form.addRow(self.title_label); form.addRow("Published:", self.published_label); form.addRow("Category:", self.categories_label)
        form.addRow("Author:", self.author_label); form.addRow(self.summary_label); form.addRow("Source:", self.source_label)
        layout.addWidget(card)
        self.feed_status_group = QGroupBox("Feed status")
        self.feed_status_group.setObjectName("threatNewsFeedStatusGroup")
        feed_status_layout = QVBoxLayout(self.feed_status_group)
        self.cache_label = QLabel(); self.cache_label.setObjectName("threatNewsCacheStatus")
        self.status_label = QLabel(); self.status_label.setObjectName("threatNewsRefreshStatus")
        for label in (self.cache_label, self.status_label):
            label.setWordWrap(True)
            label.setMinimumWidth(0)
            label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.cache_label.setAccessibleName("Threat news cache and offline status")
        self.status_label.setAccessibleName("Threat news refresh result")
        self.status_label.setStyleSheet("font-weight: 650;")
        feed_status_layout.addWidget(self.cache_label)
        feed_status_layout.addWidget(self.status_label)
        layout.addWidget(self.feed_status_group)
        self.read_button = QPushButton("Read Original Article")
        layout.addWidget(self.read_button)
        navigation = QHBoxLayout()
        self.newer_button = QPushButton("Newer"); self.older_button = QPushButton("Older")
        self.surprise_button = QPushButton("Surprise Me"); self.latest_button = QPushButton("Show Latest")
        for button in (self.newer_button, self.older_button, self.surprise_button, self.latest_button): navigation.addWidget(button)
        navigation.addStretch(); layout.addLayout(navigation)
        self.refresh_button = QPushButton("Refresh Feed")
        layout.addWidget(self.refresh_button)
        self.read_button.clicked.connect(self.open_article); self.newer_button.clicked.connect(lambda: self._show(self.navigator.newer()))
        self.older_button.clicked.connect(lambda: self._show(self.navigator.older())); self.surprise_button.clicked.connect(lambda: self._show(self.navigator.surprise()))
        self.latest_button.clicked.connect(lambda: self._show(self.navigator.latest())); self.refresh_button.clicked.connect(lambda: self.refresh_feed(manual=True))
        self.filter_mode.currentTextChanged.connect(self._filter_changed); self.external_enabled.toggled.connect(self._external_toggled)
        self.auto_refresh.toggled.connect(self._automatic_toggled); self.auto_advance.toggled.connect(self._auto_advance_toggled)

    def _reload_settings(self) -> None:
        self.external_enabled.setChecked(self._boolean(self.preferences.value("enabled", True), True))
        self.auto_refresh.setChecked(self._boolean(self.preferences.value("automatic_refresh", False), False))
        self.auto_advance.setChecked(self._boolean(self.preferences.value("auto_advance_latest", False), False))
        selected = str(self.preferences.value("filter_mode", NewsFilterMode.MALWARE_FOCUSED.value))
        self.filter_mode.setCurrentText(selected if selected in {mode.value for mode in NewsFilterMode} else NewsFilterMode.MALWARE_FOCUSED.value)
        self._settings = self._current_settings()
        self._coordinator = NewsRefreshCoordinator(self.repository, self._settings)

    def _current_settings(self) -> NewsSettings:
        return NewsSettings(
            enabled=self.external_enabled.isChecked(), automatic_refresh=self.auto_refresh.isChecked(),
            auto_advance_latest=self.auto_advance.isChecked(),
            filter_mode=NewsFilterMode(self.filter_mode.currentText()),
        )

    def _reset_coordinator(self) -> None:
        self._settings = self._current_settings(); self._coordinator = NewsRefreshCoordinator(self.repository, self._settings)

    def _filter_changed(self, value: str) -> None:
        self.preferences.setValue("filter_mode", value); self._reset_coordinator(); self._load_cache(preserve=False)

    def _external_toggled(self, enabled: bool) -> None:
        self.preferences.setValue("enabled", enabled); self._reset_coordinator(); self._apply_auto_timer(); self._load_cache()

    def _automatic_toggled(self, enabled: bool) -> None:
        self.preferences.setValue("automatic_refresh", enabled); self._reset_coordinator(); self._apply_auto_timer()

    def _auto_advance_toggled(self, enabled: bool) -> None:
        self.preferences.setValue("auto_advance_latest", enabled); self._reset_coordinator()

    def _apply_auto_timer(self) -> None:
        if not hasattr(self, "auto_timer"): return
        if self.external_enabled.isChecked() and self.auto_refresh.isChecked(): self.auto_timer.start(60 * 60 * 1000)
        else: self.auto_timer.stop()

    def _load_cache(self, preserve: bool = True, auto_advance: bool = False) -> None:
        try: articles = self.repository.list_articles(NewsFilterMode(self.filter_mode.currentText()))
        except Exception:
            LOGGER.exception("thn_news_cache_failure operation=read"); articles = []; self.status_label.setText("The local news cache could not be read.")
        self.navigator.replace(articles, preserve=preserve, auto_advance_latest=auto_advance)
        self._show(self.navigator.current)

    def _show(self, article) -> None:
        disabled = not self.external_enabled.isChecked()
        if article is None:
            self.title_label.setText("No news stories are currently available.")
            if disabled: message = "External news access is disabled. No network requests will be made."
            elif self.filter_mode.currentText() == NewsFilterMode.MALWARE_FOCUSED.value and self.repository.list_articles(NewsFilterMode.ALL_CYBERSECURITY):
                message = "No malware-focused stories are cached. Select All Cybersecurity News or refresh the feed."
            else: message = "MSAA could not retrieve The Hacker News feed. Check the network connection or try again later."
            self.summary_label.setText(message); self.published_label.clear(); self.categories_label.clear(); self.author_label.clear()
            self.cache_label.setText("External news access disabled" if disabled else "No cached article")
        else:
            self.title_label.setText(article.title)
            self.published_label.setText(article.published_at_utc.strftime("%B %d, %Y at %H:%M UTC"))
            self.categories_label.setText(" / ".join(article.categories) if article.categories else "Not provided")
            self.author_label.setText(article.author or "Not provided")
            self.summary_label.setText(article.summary_text); last = self.repository.last_successful_refresh()
            if disabled: prefix = "External news access disabled · Cached article · "
            elif self._offline: prefix = "Cached article · Offline · "
            else: prefix = "Cached article · "
            refresh = last.strftime("%B %d, %Y at %H:%M UTC") if last else "Not yet refreshed successfully"
            self.cache_label.setText(f"{prefix}Last successful feed update: {refresh}")
        available = article is not None
        self.read_button.setEnabled(available); self.surprise_button.setEnabled(len(self.navigator.articles) > 1)
        self.newer_button.setEnabled(self.navigator.can_newer); self.older_button.setEnabled(self.navigator.can_older)
        self.latest_button.setEnabled(available and self.navigator.index != 0); self.refresh_button.setEnabled(not disabled and self._thread is None)

    @Slot()
    def refresh_feed(self, manual: bool = True) -> None:
        if self._shutting_down:
            return
        accepted, message = self._coordinator.begin(manual=manual)
        if not accepted:
            self.status_label.setText(message); return
        self.refresh_button.setEnabled(False); self.status_label.setText("Refreshing The Hacker News feed…")
        self._thread = QThread(self); self._worker = _RefreshWorker(self._coordinator, self.navigator.current_article_id)
        self._worker.moveToThread(self._thread); self._thread.started.connect(self._worker.run)
        self._worker.completed.connect(self._refresh_completed); self._worker.failed.connect(self._refresh_failed)
        self._worker.completed.connect(self._thread.quit); self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater); self._thread.finished.connect(self._thread_finished)
        self._thread.start()

    @Slot(object)
    def _refresh_completed(self, result) -> None:
        self._offline = False
        self.status_label.setText(f"Feed refreshed: {result.valid} valid, {result.rejected} rejected, {result.cached} new cached stories.")
        self._load_cache(preserve=True, auto_advance=self._settings.auto_advance_latest)

    @Slot(str)
    def _refresh_failed(self, message: str) -> None:
        self._offline = True; self.status_label.setText(message); self._load_cache(preserve=True)

    @Slot()
    def _thread_finished(self) -> None:
        if self._thread: self._thread.deleteLater()
        self._thread = None; self._worker = None; self.refresh_button.setEnabled(self.external_enabled.isChecked())

    def shutdown(self, timeout_ms: int = 3000) -> bool:
        self._shutting_down = True
        self.auto_timer.stop()
        thread = self._thread
        if thread is None or not thread.isRunning():
            return True
        thread.requestInterruption(); thread.quit()
        if thread.wait(timeout_ms):
            return True
        thread.terminate()
        return thread.wait(500)

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)

    def open_article(self) -> None:
        article = self.navigator.current
        validated = normalize_article_url(article.canonical_url) if article else None
        if not validated:
            self.status_label.setText("This article link is no longer available or did not pass validation."); return
        QDesktopServices.openUrl(QUrl(validated))
        LOGGER.info("thn_news_external_article_opened source=The_Hacker_News")

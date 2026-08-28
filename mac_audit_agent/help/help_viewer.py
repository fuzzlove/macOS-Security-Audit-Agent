from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QApplication,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)
import json
import logging

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.help.glossary import GLOSSARY
from mac_audit_agent.help.help_registry import HelpTopic, get_help_topic, get_related_topics, list_help_topics, search_help_topics
from mac_audit_agent.help.diagnostic_registry import DOCUMENTATION_BUNDLE_VERSION, resolve_help_topic, validate_diagnostic_registry

MISSING_TOPIC_MESSAGE = "Documentation for this diagnostic could not be loaded."


class HelpViewer(QDialog):
    def __init__(self, topic_id: str = "help_center", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("helpCenterViewer")
        self.setWindowTitle("MSAA Help")
        self.resize(1040, 720)
        self.current_topic_id = ""
        self._build_ui()
        self._load_navigation(list_help_topics())
        self.open_topic(topic_id)

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search help")
        self.search_field.textChanged.connect(self._search)
        self.topic_list = QListWidget()
        self.topic_list.currentItemChanged.connect(self._topic_selected)
        left_layout.addWidget(self.search_field)
        left_layout.addWidget(self.topic_list)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.title_label = QLabel("")
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet("font-size: 22px; font-weight: 700;")
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("font-weight: 600;")
        self.content_view = QTextBrowser()
        self.content_view.setOpenExternalLinks(False)
        self.content_view.anchorClicked.connect(lambda url: self.open_topic(url.toString()))
        fallback_actions = QHBoxLayout()
        self.copy_diagnostic_button = QPushButton("Copy Diagnostic Details")
        self.copy_diagnostic_button.setToolTip("Copy sanitized help-resolution details to the clipboard.")
        self.copy_diagnostic_button.clicked.connect(lambda: QApplication.clipboard().setText(self.content_view.toPlainText()))
        self.view_logs_button = QPushButton("View Application Logs")
        self.view_logs_button.setToolTip("Open the supported MSAA logs view when it is available.")
        self.view_logs_button.setEnabled(False)
        self.integrity_button = QPushButton("Run Documentation Integrity Check")
        self.integrity_button.setToolTip("Validate registered diagnostic topics and packaged documentation resources.")
        self.integrity_button.clicked.connect(self._show_integrity_result)
        for button in (self.copy_diagnostic_button, self.view_logs_button, self.integrity_button):
            button.hide()
            fallback_actions.addWidget(button)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        right_layout.addWidget(self.title_label)
        right_layout.addWidget(self.summary_label)
        right_layout.addWidget(self.content_view, 1)
        right_layout.addLayout(fallback_actions)
        right_layout.addWidget(close_button, alignment=Qt.AlignRight)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([300, 740])

    def _load_navigation(self, topics: list[HelpTopic]) -> None:
        self.topic_list.blockSignals(True)
        self.topic_list.clear()
        for topic in topics:
            item = QListWidgetItem(f"{topic.feature_area}: {topic.title}")
            item.setData(Qt.UserRole, topic.topic_id)
            self.topic_list.addItem(item)
        self.topic_list.blockSignals(False)

    def _topic_selected(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is not None:
            self.open_topic(str(current.data(Qt.UserRole)))

    def _search(self, query: str) -> None:
        if not query.strip():
            self._load_navigation(list_help_topics())
            if self.current_topic_id:
                self._select_topic_item(self.current_topic_id)
            return
        results = search_help_topics(query)
        self._load_navigation(results)
        if results:
            self.open_topic(results[0].topic_id)
        else:
            self.current_topic_id = ""
            self.title_label.setText("No Results")
            self.summary_label.setText(f"No help results found for: {query}")
            self.content_view.setPlainText(f"No help results found for: {query}")

    def open_topic(self, topic_id) -> None:
        resolution = resolve_help_topic(topic_id)
        topic = resolution.topic
        if topic is None and resolution.reason == "topic_not_registered":
            topic = get_help_topic(topic_id)
        self.current_topic_id = str(topic_id)
        if topic is None:
            requested = str(topic_id).strip() or "(empty)"
            self.title_label.setText("Documentation Could Not Be Loaded")
            self.summary_label.setText(MISSING_TOPIC_MESSAGE)
            try:
                identity = detect_build_identity()
                app_version, build_id = identity.app_version, identity.build_id or "not configured"
            except Exception:
                app_version, build_id = "unknown", "unknown"
            event = resolution.failure_event(application_version=app_version, build_id=build_id)
            details = [MISSING_TOPIC_MESSAGE, "", f"Requested topic identifier: {requested}",
                f"Normalized topic: {resolution.normalized_topic or '(empty)'}", f"Error code: {resolution.normalized_topic if resolution.normalized_topic.startswith('AR') else 'not available'}",
                f"Originating module: {resolution.module}", f"Application version: {app_version}", f"Build identifier: {build_id}",
                f"Documentation bundle version: {DOCUMENTATION_BUNDLE_VERSION}", f"Expected resource: {resolution.expected_resource or 'not registered'}",
                f"Reason: {resolution.reason or 'topic_not_registered'}"]
            self.content_view.setPlainText("\n".join(details))
            for button in (self.copy_diagnostic_button, self.view_logs_button, self.integrity_button):
                button.show()
            logging.getLogger("msaa.help").error("help_topic_resolution_failed %s", json.dumps(event, sort_keys=True))
            return
        for button in (self.copy_diagnostic_button, self.view_logs_button, self.integrity_button):
            button.hide()
        self.title_label.setText(topic.title)
        self.summary_label.setText(topic.summary)
        if topic.resource_content:
            self.content_view.setMarkdown(topic.resource_content)
        else:
            self.content_view.setHtml(self._topic_html(topic))
        self._select_topic_item(topic.topic_id)

    def _show_integrity_result(self) -> None:
        failures = validate_diagnostic_registry()
        self.content_view.setPlainText("Documentation integrity check passed." if not failures else json.dumps({"failures":failures}, indent=2))

    def _select_topic_item(self, topic_id: str) -> None:
        self.topic_list.blockSignals(True)
        for index in range(self.topic_list.count()):
            item = self.topic_list.item(index)
            if item.data(Qt.UserRole) == topic_id:
                self.topic_list.setCurrentItem(item)
                break
        self.topic_list.blockSignals(False)

    def _topic_html(self, topic: HelpTopic) -> str:
        paragraphs = "".join(f"<p>{line}</p>" for line in topic.content.split("\n\n") if line.strip())
        related = "".join(f'<li><a href="{related.topic_id}">{related.title}</a></li>' for related in get_related_topics(topic.topic_id))
        glossary = "".join(
            f"<li><b>{term}</b>: {GLOSSARY.get(term, GLOSSARY.get(term.title(), 'Open Help for more.'))}</li>"
            for term in topic.glossary_terms
        )
        about_metadata = self._about_metadata_html() if topic.topic_id == "about_msaa" else ""
        return f"""
        <html><body>
        <p><b>Audience:</b> {topic.audience}</p>
        <p><b>Feature area:</b> {topic.feature_area}</p>
        {paragraphs}
        {about_metadata}
        <h3>Related Topics</h3>
        <ul>{related or "<li>No related topics configured.</li>"}</ul>
        <h3>Glossary Terms</h3>
        <ul>{glossary or "<li>No glossary terms configured.</li>"}</ul>
        <p><b>Last updated:</b> {topic.last_updated}</p>
        </body></html>
        """

    def _about_metadata_html(self) -> str:
        try:
            identity = detect_build_identity()
        except Exception as exc:
            return f"<h3>Installed Build</h3><p>Build metadata unavailable: {exc}</p>"
        rows = [
            ("App name", identity.app_name),
            ("Version", identity.app_version),
            ("Build", identity.build_id or "not configured"),
            ("Package version", identity.package_version or "not installed as a package"),
            ("Install mode", identity.install_mode),
            ("Git commit", identity.git_commit or "not available"),
            ("License", "MIT"),
            ("Author/company", "Mac Audit Agent contributors"),
            ("Website", "https://github.com/fuzzlove/macOS-Security-Audit-Agent"),
            ("Executable", identity.executable_path),
            ("Runtime root", identity.runtime_root),
        ]
        rendered = "".join(f"<tr><th align='left'>{label}</th><td>{value}</td></tr>" for label, value in rows)
        return f"<h3>Installed Build</h3><table>{rendered}</table>"

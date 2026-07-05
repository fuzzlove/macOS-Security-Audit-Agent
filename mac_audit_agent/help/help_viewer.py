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
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.help.glossary import GLOSSARY
from mac_audit_agent.help.help_registry import HelpTopic, get_help_topic, get_related_topics, list_help_topics, search_help_topics

MISSING_TOPIC_MESSAGE = "Help topic unavailable. This is a documentation bug."


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
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        right_layout.addWidget(self.title_label)
        right_layout.addWidget(self.summary_label)
        right_layout.addWidget(self.content_view, 1)
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

    def open_topic(self, topic_id: str) -> None:
        topic = get_help_topic(topic_id)
        self.current_topic_id = topic_id
        if topic is None:
            self.title_label.setText("Help Topic Unavailable")
            self.summary_label.setText(MISSING_TOPIC_MESSAGE)
            self.content_view.setPlainText(MISSING_TOPIC_MESSAGE)
            return
        self.title_label.setText(topic.title)
        self.summary_label.setText(topic.summary)
        self.content_view.setHtml(self._topic_html(topic))
        self._select_topic_item(topic.topic_id)

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

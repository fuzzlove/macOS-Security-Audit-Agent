from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from mac_audit_agent.version import APP_VERSION


ETHICS_CURRICULUM_VERSION = "1.0"
ETHICS_SCHEMA_VERSION = "1.0"
ETHICS_PASS_PERCENT = 100
ETHICS_LESSON = """MSAA Computer Science Ethics — Basic Authorized-Use Class

Computers can affect privacy, finances, safety, employment, reputation, access to services, and the availability of essential systems. Even technically reversible actions can cause real harm when performed without permission, adequate testing, or respect for affected people.

Core responsibilities

1. Authorization and scope. Use security capabilities only on systems, accounts, networks, and data covered by current explicit authorization. A license, job title, NDA, emergency claim, or EULA acceptance is not target authorization.

2. Avoid and minimize harm. Prefer read-only, least-privileged, reversible methods. Stop when scope, ownership, safety, privacy, or likely impact is unclear. Do not use MSAA to retaliate, disrupt services, conceal activity, or gain unauthorized access.

3. Privacy and dignity. Collect only evidence needed for the approved purpose. Protect sensitive information, avoid unnecessary personal data, redact before sharing, and follow retention and classification requirements.

4. Accuracy and uncertainty. A finding, score, CVE association, AI response, or alert may be incomplete or wrong. Missing telemetry is not proof of safety. Verify material claims before consequential action and distinguish evidence from inference.

5. Human accountability. Qualified people remain responsible for decisions. Preserve evidence, document approvals, consider downstream effects, use safe rollback and recovery, and escalate legal, privacy, safety, or incident concerns.

Passing this short assessment records that the user demonstrated these basic concepts for this curriculum version. It does not certify ethical conduct, grant system authorization, establish competence, or replace the EULA and rules of engagement."""


@dataclass(frozen=True)
class EthicsQuestion:
    prompt: str
    choices: tuple[str, ...]
    correct_index: int


QUESTIONS = (
    EthicsQuestion("When may MSAA be used to assess a third-party system?", ("When the user has current explicit authorization covering the target and action", "Whenever an NDA exists", "Whenever MSAA is licensed"), 0),
    EthicsQuestion("What should happen when an action may create unexpected harm or exceed scope?", ("Continue if the tool reports high confidence", "Stop, preserve relevant evidence, and obtain qualified direction", "Hide the action from logs"), 1),
    EthicsQuestion("How should sensitive evidence be handled?", ("Collect everything in case it becomes useful", "Upload it to any convenient service", "Minimize, protect, redact, and retain it only as authorized"), 2),
    EthicsQuestion("What does missing telemetry establish?", ("The control passed", "Nothing occurred", "Visibility is incomplete; safety has not been proven"), 2),
    EthicsQuestion("How should a material alert, CVE mapping, or AI-generated claim be used?", ("Treat it as proven", "Independently validate it before consequential action", "Use it to attribute an individual immediately"), 1),
    EthicsQuestion("What does accepting the MSAA EULA authorize?", ("Use of the software under its terms, but not access to a target", "Any defensive action", "Access to any system owned by the user's employer"), 0),
)


def default_ethics_state_path() -> Path:
    return Path.home() / ".mac_audit_agent" / "governance" / "ethics-completion.json"


def default_ethics_event_path() -> Path:
    return Path.home() / ".mac_audit_agent" / "governance" / "ethics-events.jsonl"


def ethics_user_reference() -> str:
    return "local-user-" + hashlib.sha256(str(os.getuid()).encode("ascii")).hexdigest()[:16]


def curriculum_digest() -> str:
    content = json.dumps({"lesson": ETHICS_LESSON, "questions": [question.__dict__ for question in QUESTIONS]}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def grade_ethics_answers(answers: tuple[int, ...] | list[int]) -> tuple[int, bool]:
    if len(answers) != len(QUESTIONS) or any(isinstance(answer, bool) or not isinstance(answer, int) for answer in answers):
        return 0, False
    correct = sum(answer == question.correct_index for answer, question in zip(answers, QUESTIONS))
    percent = round(correct * 100 / len(QUESTIONS))
    return percent, percent >= ETHICS_PASS_PERCENT


def _read_state(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def ethics_completion_is_current(state_path: Path | None = None, *, user_reference: str | None = None) -> bool:
    payload = _read_state(state_path or default_ethics_state_path())
    return bool(payload and payload.get("passed") is True and payload.get("schema_version") == ETHICS_SCHEMA_VERSION and payload.get("curriculum_version") == ETHICS_CURRICULUM_VERSION and payload.get("curriculum_sha256") == curriculum_digest() and payload.get("user_reference") == (user_reference or ethics_user_reference()))


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path); os.chmod(path, 0o600)
    except Exception:
        try: temporary.unlink(missing_ok=True)
        except OSError: pass
        raise


def _append_completion_event(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        event = {"schema_version": ETHICS_SCHEMA_VERSION, "event_id": f"ethics-{uuid4().hex}", "event_type": "governance_ethics_class_passed", "passed_at": payload["passed_at"], "curriculum_version": ETHICS_CURRICULUM_VERSION, "curriculum_sha256": payload["curriculum_sha256"], "application_version": APP_VERSION, "user_reference": payload["user_reference"], "score_percent": payload["score_percent"], "answers_recorded": False, "authorization_granted": False}
        os.write(descriptor, (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")); os.fsync(descriptor)
    finally:
        os.close(descriptor)


def record_ethics_completion(*, score_percent: int, state_path: Path | None = None, event_path: Path | None = None, user_reference: str | None = None) -> dict[str, object]:
    if score_percent < ETHICS_PASS_PERCENT:
        raise ValueError("A passing score is required before recording ethics completion.")
    timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    payload: dict[str, object] = {"schema_version": ETHICS_SCHEMA_VERSION, "curriculum_version": ETHICS_CURRICULUM_VERSION, "curriculum_sha256": curriculum_digest(), "passed": True, "passed_at": timestamp, "score_percent": score_percent, "user_reference": user_reference or ethics_user_reference(), "application_version": APP_VERSION, "monitor_event_pending": True, "answers_recorded": False, "authorization_granted": False}
    _append_completion_event(event_path or default_ethics_event_path(), payload)
    _atomic_json(state_path or default_ethics_state_path(), payload)
    return payload


class ComputerScienceEthicsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent); self.passed = False; self.score_percent = 0
        self.setWindowTitle("Required MSAA Computer Science Ethics Class"); self.resize(820, 760)
        layout = QVBoxLayout(self)
        heading = QLabel("<b>Complete this one-time basic ethics class before reviewing the EULA.</b>"); heading.setWordWrap(True); layout.addWidget(heading)
        lesson = QLabel(ETHICS_LESSON); lesson.setWordWrap(True); lesson.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        content = QWidget(); content_layout = QVBoxLayout(content); content_layout.addWidget(lesson)
        self.answer_boxes: list[QComboBox] = []
        for number, question in enumerate(QUESTIONS, 1):
            prompt = QLabel(f"{number}. {question.prompt}"); prompt.setWordWrap(True); prompt.setStyleSheet("font-weight: 650;"); content_layout.addWidget(prompt)
            box = QComboBox(); box.addItem("Select an answer…", -1)
            for index, choice in enumerate(question.choices): box.addItem(choice, index)
            box.setAccessibleName(f"Ethics question {number}"); self.answer_boxes.append(box); content_layout.addWidget(box)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content); layout.addWidget(scroll, 1)
        self.result = QLabel("A score of 100% is required. Incorrect answers can be reviewed and retried."); self.result.setWordWrap(True); layout.addWidget(self.result)
        buttons = QDialogButtonBox(); submit = buttons.addButton("Submit Ethics Assessment", QDialogButtonBox.AcceptRole); decline = buttons.addButton("Exit MSAA", QDialogButtonBox.RejectRole)
        submit.clicked.connect(self._grade); decline.clicked.connect(self.reject); layout.addWidget(buttons)

    def _grade(self) -> None:
        answers = [int(box.currentData()) for box in self.answer_boxes]
        self.score_percent, self.passed = grade_ethics_answers(answers)
        if self.passed:
            self.result.setText("Passed. You demonstrated the basic concepts in this curriculum. This does not grant target authorization."); self.accept(); return
        self.result.setText(f"Score: {self.score_percent}%. Review the lesson and incorrect concepts, then try again.")
        QMessageBox.warning(self, "Ethics Assessment Not Yet Passed", "Review the class and try again. MSAA cannot continue to the EULA until all basic concepts are answered correctly.")


def require_ethics_completion(parent=None, *, state_path: Path | None = None, event_path: Path | None = None, user_reference: str | None = None) -> bool:
    if ethics_completion_is_current(state_path, user_reference=user_reference):
        return True
    dialog = ComputerScienceEthicsDialog(parent)
    if dialog.exec() != QDialog.Accepted or not dialog.passed:
        return False
    try:
        record_ethics_completion(score_percent=dialog.score_percent, state_path=state_path, event_path=event_path, user_reference=user_reference)
    except OSError:
        QMessageBox.critical(parent, "Ethics Completion Could Not Be Saved", "MSAA could not securely save the required completion record. No EULA acceptance or application access will proceed.")
        return False
    return True


def pending_ethics_monitor_event(state_path: Path | None = None) -> dict[str, object] | None:
    payload = _read_state(state_path or default_ethics_state_path())
    return payload if payload and payload.get("monitor_event_pending") is True and ethics_completion_is_current(state_path, user_reference=str(payload.get("user_reference"))) else None


def mark_ethics_monitor_event_recorded(state_path: Path | None = None) -> None:
    path = state_path or default_ethics_state_path(); payload = _read_state(path)
    if not payload: return
    payload["monitor_event_pending"] = False; payload["monitor_event_recorded_at"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"); _atomic_json(path, payload)


__all__ = ["ETHICS_CURRICULUM_VERSION", "ETHICS_LESSON", "ComputerScienceEthicsDialog", "ethics_completion_is_current", "grade_ethics_answers", "pending_ethics_monitor_event", "record_ethics_completion", "require_ethics_completion", "mark_ethics_monitor_event_recorded"]

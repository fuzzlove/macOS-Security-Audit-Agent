from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QDialog

from mac_audit_agent import app
from mac_audit_agent.ui.ethics_class import (
    ETHICS_CURRICULUM_VERSION,
    QUESTIONS,
    ComputerScienceEthicsDialog,
    ethics_completion_is_current,
    grade_ethics_answers,
    mark_ethics_monitor_event_recorded,
    pending_ethics_monitor_event,
    record_ethics_completion,
    require_ethics_completion,
)


def correct_answers():
    return [question.correct_index for question in QUESTIONS]


def test_ethics_assessment_requires_all_basic_concepts():
    score, passed = grade_ethics_answers(correct_answers())
    assert (score, passed) == (100, True)
    answers = correct_answers(); answers[0] = (answers[0] + 1) % len(QUESTIONS[0].choices)
    score, passed = grade_ethics_answers(answers)
    assert score < 100 and passed is False
    assert grade_ethics_answers([]) == (0, False)


def test_completion_is_one_time_versioned_private_and_does_not_store_answers(tmp_path):
    state = tmp_path / "state/ethics.json"; events = tmp_path / "events/ethics.jsonl"
    payload = record_ethics_completion(score_percent=100, state_path=state, event_path=events, user_reference="pseudonym")
    assert ethics_completion_is_current(state, user_reference="pseudonym")
    assert state.stat().st_mode & 0o777 == 0o600
    assert events.stat().st_mode & 0o777 == 0o600
    persisted = state.read_text() + events.read_text()
    assert "answers" not in persisted or '"answers_recorded": false' in persisted
    assert payload["authorization_granted"] is False
    assert payload["curriculum_version"] == ETHICS_CURRICULUM_VERSION


def test_nonpassing_score_cannot_be_cached(tmp_path):
    with pytest.raises(ValueError, match="passing score"):
        record_ethics_completion(score_percent=99, state_path=tmp_path/"state.json", event_path=tmp_path/"events.jsonl")


def test_cached_completion_skips_dialog(tmp_path, monkeypatch):
    state=tmp_path/"state.json";events=tmp_path/"events.jsonl"
    record_ethics_completion(score_percent=100,state_path=state,event_path=events,user_reference="u")
    monkeypatch.setattr("mac_audit_agent.ui.ethics_class.ComputerScienceEthicsDialog",lambda *_:pytest.fail("dialog should not open"))
    assert require_ethics_completion(state_path=state,event_path=events,user_reference="u")


def test_dialog_pass_must_precede_completion_record(tmp_path, monkeypatch):
    application=QApplication.instance() or QApplication([])
    def pass_dialog(dialog):
        for box, question in zip(dialog.answer_boxes, QUESTIONS): box.setCurrentIndex(question.correct_index + 1)
        dialog._grade(); return QDialog.Accepted
    monkeypatch.setattr(ComputerScienceEthicsDialog,"exec",pass_dialog)
    state=tmp_path/"state.json";events=tmp_path/"events.jsonl"
    assert require_ethics_completion(state_path=state,event_path=events,user_reference="u")
    assert ethics_completion_is_current(state,user_reference="u")
    application.processEvents()


def test_pending_monitor_event_is_consumed_only_after_record(tmp_path):
    state=tmp_path/"state.json";events=tmp_path/"events.jsonl"
    record_ethics_completion(score_percent=100,state_path=state,event_path=events,user_reference="u")
    assert pending_ethics_monitor_event(state) is not None
    mark_ethics_monitor_event_recorded(state)
    assert pending_ethics_monitor_event(state) is None


def test_ethics_monitor_event_contains_no_answers_or_authorization(monkeypatch):
    completion={"schema_version":"1.0","curriculum_version":"1.0","curriculum_sha256":"a"*64,"passed_at":"2026-01-01T00:00:00.000Z","score_percent":100,"user_reference":"pseudonym","application_version":"1","answers_recorded":False,"authorization_granted":False}
    monkeypatch.setattr(app,"pending_ethics_monitor_event",lambda:completion)
    marked=[];monkeypatch.setattr(app,"mark_ethics_monitor_event_recorded",lambda:marked.append(True))
    class DB:
        def __init__(self):self.events=[]
        def record_monitor_event(self,event,dedupe_window_seconds=300):self.events.append(event);return True
    window=type("Window",(),{"db":DB()})()
    app._record_pending_ethics_monitor_event(window)
    event=window.db.events[0];metadata=json.loads(event.metadata_json)
    assert event.event_type == "governance_ethics_class_passed"
    assert metadata["answers_recorded"] is False and metadata["authorization_granted"] is False
    assert "answers" not in metadata
    assert marked == [True]


def test_startup_governance_order_is_ethics_before_each_launch_eula(monkeypatch):
    calls=[]
    monkeypatch.setattr(app,"preview_startup_notice",lambda:calls.append("preview") or True)
    monkeypatch.setattr(app,"require_ethics_completion",lambda:calls.append("ethics") or True)
    monkeypatch.setattr(app,"require_current_eula_acceptance",lambda:calls.append("eula") or True)
    assert app._run_governance_gates()
    assert calls == ["preview","ethics","eula"]


def test_eula_is_not_shown_when_ethics_gate_is_declined(monkeypatch):
    calls=[]
    monkeypatch.setattr(app,"preview_startup_notice",lambda:True)
    monkeypatch.setattr(app,"require_ethics_completion",lambda:False)
    monkeypatch.setattr(app,"require_current_eula_acceptance",lambda:calls.append("eula") or True)
    assert app._run_governance_gates() is False
    assert calls == []

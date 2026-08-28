from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from mac_audit_agent.anti_ransomware.health import RuntimeEvidence, source_health
from mac_audit_agent.help.diagnostic_registry import (
    DIAGNOSTIC_TOPICS,
    DiagnosticTopic,
    normalize_help_identifier,
    resolve_help_topic,
    validate_diagnostic_registry,
)
from mac_audit_agent.help.documentation_integrity import validate_documentation
from mac_audit_agent.help.help_registry import get_help_topic


def test_help_viewer_renders_ar022_and_actionable_fallback():
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from mac_audit_agent.help.help_viewer import HelpViewer, MISSING_TOPIC_MESSAGE
    app = QApplication.instance() or QApplication([])
    viewer = HelpViewer("AR022")
    assert viewer.current_topic_id == "AR022"
    assert viewer.title_label.text() == "Anti-Ransomware Protection Is Running in Degraded Observation Mode"
    assert "Detected Conditions" in viewer.content_view.toPlainText()
    viewer.open_topic("unknown-diagnostic")
    fallback = viewer.content_view.toPlainText()
    assert MISSING_TOPIC_MESSAGE in fallback
    assert "unknown-diagnostic" in fallback
    assert viewer.copy_diagnostic_button.text() == "Copy Diagnostic Details"
    assert not viewer.copy_diagnostic_button.isHidden()
    assert viewer.integrity_button.toolTip()
    viewer.close()
    app.processEvents()


def test_ar022_code_slug_whitespace_case_and_dictionary_resolve():
    for identifier in ("AR022", " ar022 ", "anti-ransomware-degraded-observation", {"error_code":"AR022"}, '{"error_code":"AR022"}'):
        topic = get_help_topic(identifier)
        assert topic is not None
        assert topic.topic_id == "anti-ransomware-degraded-observation"
        assert topic.title == "Anti-Ransomware Protection Is Running in Degraded Observation Mode"
        assert topic.resource_content.startswith("# Anti-Ransomware Protection")
    assert normalize_help_identifier("anti_ransomware:ar022") == "AR022"


def test_representative_cross_module_diagnostics_resolve():
    for code in ("PY001", "DEP001", "MON001", "STD004"):
        topic = get_help_topic(code)
        assert topic is not None and topic.resource_content.startswith("# ")


def test_ar022_content_is_complete_and_truthful():
    topic = get_help_topic(source_health(evidence=RuntimeEvidence(system_engine_running=True)).to_dict())
    assert topic is not None
    content = topic.resource_content
    for text in ("Current State", "Detected Conditions", "Security Impact", "Likely Causes", "Development Environment", "Signed Production Build", "Full Disk Access", "Apple controls"):
        assert text in content
    assert "pip" in content
    assert "full ransomware protection" not in content.lower()


def test_fallback_and_missing_resource_report_structured_reason(monkeypatch):
    unresolved = resolve_help_topic("DOES-NOT-EXIST")
    assert unresolved.reason == "topic_not_registered"
    assert unresolved.failure_event()["requested_topic"] == "DOES-NOT-EXIST"
    monkeypatch.setitem(DIAGNOSTIC_TOPICS, "AR022", replace(DIAGNOSTIC_TOPICS["AR022"], resource="anti_ransomware/missing.md"))
    missing = resolve_help_topic("AR022")
    assert missing.reason == "resource_missing"
    assert missing.failure_event()["expected_resource"] == "anti_ransomware/missing.md"


def test_duplicate_slugs_and_aliases_fail_validation():
    first = DIAGNOSTIC_TOPICS["AR001"]
    duplicate = DiagnosticTopic("AR999", first.slug, "Duplicate", "Duplicate", first.resource, aliases=first.aliases)
    failures = validate_diagnostic_registry(registry={"AR001":first, "AR999":duplicate})
    assert {item["reason"] for item in failures} >= {"duplicate_code_or_slug", "alias_conflict"}


def test_every_emitted_anti_ransomware_code_has_packaged_documentation():
    root = Path(__file__).resolve().parents[1]
    result = validate_documentation(root)
    assert result["valid"], result["failures"]
    assert set(result["emitted_codes"]).issubset(result["registered_codes"])


def test_markdown_resources_are_declared_for_all_packagers():
    root = Path(__file__).resolve().parents[1]
    assert "help/resources/**/*.md" in (root / "Mac Audit Agent.spec").read_text()
    assert "recursive-include mac_audit_agent/help/resources *.md" in (root / "MANIFEST.in").read_text()
    assert '"help/resources/**/*.md"' in (root / "pyproject.toml").read_text()

import json
from pathlib import Path

import pytest

from mac_audit_agent.ai_security_analyst import AISecurityAnalyst, AnalystAssistantError, AnalystAuditStore, SharingPolicy, minimize_evidence


def finding():
    return {"finding_id": "p-1", "title": "Unsigned LaunchAgent detected", "severity": "high", "confidence": "high", "mechanism": "launch_agent", "path": "/Users/alice/Library/LaunchAgents/test.plist", "executable_path": "/private/tmp/tool", "signature_status": "unsigned", "sha256": "a" * 64, "mitre_attack": ["T1543.001"], "evidence": ["RunAtLoad enabled"], "password": "must-not-leak"}


def test_local_explanation_separates_fact_interpretation_uncertainty_and_logs(tmp_path: Path) -> None:
    store = AnalystAuditStore(tmp_path / "ai.sqlite3"); assistant = AISecurityAnalyst(store)
    result = assistant.explain(finding(), question="Why is this suspicious?", user="analyst")
    assert any("Unsigned LaunchAgent" in fact for fact in result.observed_facts)
    assert any("not a malware verdict" in item for item in result.analyst_interpretation)
    assert result.human_review_required and result.confidence_score < 100
    assert result.framework_mapping["MITRE ATT&CK"] == ["T1543.001"]
    row = store.recent(1)[0]
    assert row["finding_id"] == "p-1" and "must-not-leak" not in json.dumps(row)


def test_missing_evidence_is_named_and_never_invented(tmp_path: Path) -> None:
    result = AISecurityAnalyst(AnalystAuditStore(tmp_path / "ai.sqlite3")).explain({"finding_id": "x", "title": "Unknown process", "severity": "medium"}, question="Explain", user="analyst")
    assert any("SHA-256" in value for value in result.missing_information)
    assert not any("signed by" in value.lower() for value in result.observed_facts)


def test_sensitive_fields_are_removed_and_paths_redacted() -> None:
    result = minimize_evidence(finding())
    assert "password" not in result and "alice" not in json.dumps(result)


def test_external_provider_requires_explicit_approval(tmp_path: Path) -> None:
    assistant = AISecurityAnalyst(AnalystAuditStore(tmp_path / "ai.sqlite3"))
    with pytest.raises(AnalystAssistantError, match="explicit administrator approval"):
        assistant.explain(finding(), question="Explain", user="analyst", sharing=SharingPolicy(allow_external=True))


def test_incident_summary_remains_evidence_bound(tmp_path: Path) -> None:
    summary = AISecurityAnalyst(AnalystAuditStore(tmp_path / "ai.sqlite3")).summarize_incident([finding()], user="analyst")
    assert summary["human_review_required"] is True
    assert summary["technical_summary"]["finding_ids"] == ["p-1"]

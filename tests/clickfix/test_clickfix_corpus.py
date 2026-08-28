from __future__ import annotations
import json
from pathlib import Path

from mac_audit_agent.clickfix.corpus_validation import CorrelationSession, evaluate_fixture
from mac_audit_agent.clickfix.shell_config import ShellGuardConfig
from mac_audit_agent.clickfix.shell_scanner import scan_request


def test_fixture_schema_and_classification(clickfix_fixture):
    required={"fixture_id","name","category","description","command_text","paste_origin","multiline","trailing_newline","shell","expected_decision","minimum_score","required_rule_ids","forbidden_side_effects","campaign_relevance","notes"}
    assert required <= clickfix_fixture.keys()
    result=evaluate_fixture(clickfix_fixture)
    expected=clickfix_fixture["expected_decision"]
    if expected=="allow": assert result["decision"]=="allow"
    elif expected=="warn": assert result["decision"] in {"warn","block"}
    else: assert result["decision"]=="block"
    assert result["score"] >= clickfix_fixture["minimum_score"]
    assert set(clickfix_fixture["required_rule_ids"]) <= set(result["rule_ids"])


def test_split_command_chains_retain_hashes_not_commands():
    fixtures=json.loads(Path(__file__).with_name("chain_correlation.json").read_text())
    for fixture in fixtures:
        session=CorrelationSession(fixture["fixture_id"]);result={}
        for index,command in enumerate(fixture["event_sequence"]): result=session.observe(command,float(index*10))
        assert result["decision"]=="block"
        assert set(fixture["required_rule_ids"]) <= set(result["rule_ids"])
        serialized=json.dumps(session.records)
        for command in fixture["event_sequence"]: assert command not in serialized
        assert all(len(item["command_sha256"])==64 for item in session.records)


def test_scanner_timeout_fails_visibly(monkeypatch):
    ticks=iter((0,20_000_000,20_000_001))
    monkeypatch.setattr("mac_audit_agent.clickfix.shell_scanner.time.monotonic_ns",lambda:next(ticks))
    result=scan_request({"command":"printf harmless","phase":"test","paste_origin":False},ShellGuardConfig(scanner_timeout_ms=10))
    assert result.decision=="error" and result.error=="scanner_timeout"

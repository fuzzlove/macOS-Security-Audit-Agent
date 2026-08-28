from __future__ import annotations

from types import SimpleNamespace

from mac_audit_agent.anti_ransomware.cli import main
from mac_audit_agent.anti_ransomware.yara_rule_manager import (
    YaraRuleValidationError,
    extract_rule_names,
    validate_yara_source,
)
from mac_audit_agent.anti_ransomware.yara_validation_suite import (
    MATCH_CASES,
    NONMATCH_CASES,
    run_yara_validation_suite,
    validate_active_yara_release,
)


def test_twenty_safe_yara_cases_pass_without_host_activity() -> None:
    report = run_yara_validation_suite()

    assert len(MATCH_CASES) == 12
    assert len(NONMATCH_CASES) == 3
    assert report["case_count"] == 20
    assert report["passed_count"] == 20
    assert report["failed_count"] == 0
    assert report["all_passed"] is True
    assert set(report["safety"].values()) == {False}
    assert all(item["passed"] for item in report["results"])


def test_negative_controls_produce_no_matches() -> None:
    report = run_yara_validation_suite()
    negatives = {
        item["case_id"]: item for item in report["results"]
        if item["case_id"] in {case.case_id for case in NONMATCH_CASES}
    }
    assert set(negatives) == {"YARA-SAFE-13", "YARA-SAFE-14", "YARA-SAFE-15"}
    assert all(item["matches"] == [] for item in negatives.values())


def test_duplicate_rule_names_are_preserved_then_rejected() -> None:
    source = (
        'rule DuplicateFixture { condition: false }\n'
        'rule DuplicateFixture { condition: true }\n'
    )
    assert extract_rule_names(source) == ("DuplicateFixture", "DuplicateFixture")
    try:
        validate_yara_source(source)
    except YaraRuleValidationError as exc:
        assert "unique" in str(exc)
    else:
        raise AssertionError("duplicate YARA rule names were accepted")


def test_active_release_validation_compiles_and_runs_benign_controls() -> None:
    source = 'rule ActiveFixture { strings: $a = "not-in-benign-controls" condition: $a }'
    snapshot = SimpleNamespace(
        version="fixture-release",
        manifest_sha256="a" * 64,
        yara_sources={"fixture": source},
        counts={"YARA_RULE": 1},
    )
    database = SimpleNamespace(load=lambda: snapshot)

    report = validate_active_yara_release(database=database)

    assert report["status"] == "PASS"
    assert report["release"] == "fixture-release"
    assert report["loaded_rule_count"] == 1
    assert report["unexpected_matches"] == []


def test_cli_yara_definition_profile(capsys) -> None:
    assert main([
        "simulate", "--safe", "--no-file-destruction",
        "--profile", "yara-definition-suite", "--json",
    ]) == 0
    output = capsys.readouterr().out
    assert '"case_count": 20' in output
    assert '"all_passed": true' in output

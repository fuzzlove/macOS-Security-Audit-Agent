from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

import pytest

from mac_audit_agent.anti_typosquatting.cli import main as cli_main
from mac_audit_agent.anti_typosquatting.models import AssetType, GenerationConfiguration, PackageEcosystem, ProtectedAsset
from mac_audit_agent.anti_typosquatting.normalization import confusable_skeleton, domain_ascii, normalize_pypi, visible_text
from mac_audit_agent.anti_typosquatting.persistence import AntiTyposquattingStore
from mac_audit_agent.anti_typosquatting.reporting import export_csv, export_html, export_json, export_professional
from mac_audit_agent.anti_typosquatting.service import AntiTyposquattingService
from mac_audit_agent.help.topic_registry import get_topic
from mac_audit_agent.version import APP_VERSION


def domain_run(limit=25, locale="en-US-qwerty"):
    return AntiTyposquattingService().analyze(ProtectedAsset(AssetType.DOMAIN, "examplebrand.test"), GenerationConfiguration(locales=(locale,), result_limit=limit))


def test_domain_generation_is_deterministic_bounded_and_explainable():
    first, second = domain_run(), domain_run()
    assert [item.normalized_name for item in first.candidates] == [item.normalized_name for item in second.candidates]
    assert 1 <= len(first.candidates) <= 25
    assert all(item.reasons and item.display_name != "examplebrand.test" for item in first.candidates)
    assert all(0 <= item.human_typo.total <= 100 and 0 <= item.impersonation.total <= 100 for item in first.candidates)
    assert all(0 <= item.name_closeness.total <= 100 and 0 <= item.attacker_use_assumption.total <= 100 for item in first.candidates)
    assert all(item.risk_band in {"low", "medium", "high", "critical"} for item in first.candidates)
    assert first.candidates == sorted(first.candidates, key=lambda item: (-item.attacker_use_assumption.total, -item.name_closeness.total, item.normalized_name))
    assert all("authoritative" in item.registration_guidance.lower() or "registrar" in item.registration_guidance.lower() for item in first.candidates)


def test_keyboard_locale_changes_results():
    us = {item.normalized_name for item in domain_run(locale="en-US-qwerty").candidates}
    fr = {item.normalized_name for item in domain_run(locale="fr-FR-azerty").candidates}
    assert us != fr


def test_domain_validation_and_control_safety():
    assert domain_ascii("examplebrand.test") == "examplebrand.test"
    with pytest.raises(ValueError): domain_ascii("https://examplebrand.test/path")
    with pytest.raises(ValueError): domain_ascii("exam\u202eple.test")
    assert "U+202E" in visible_text("exam\u202eple")


def test_unicode_confusable_skeleton_and_mixed_script_details():
    assert confusable_skeleton("pаypal") == confusable_skeleton("paypal")
    run = AntiTyposquattingService().analyze(ProtectedAsset(AssetType.DOMAIN, "scope.test"), GenerationConfiguration(result_limit=100))
    candidates = [item for item in run.candidates if "visual_confusable" in item.categories]
    assert candidates and any(item.unicode_code_points for item in candidates)


def test_python_normalization_collisions_are_merged():
    assert normalize_pypi("Friendly-._-Bard") == "friendly-bard"
    run = AntiTyposquattingService().analyze(ProtectedAsset(AssetType.PACKAGE, "example_python_client", PackageEcosystem.PYPI), GenerationConfiguration(result_limit=100))
    normalized = [item.normalized_name for item in run.candidates]
    assert len(normalized) == len(set(normalized))
    assert any("normalization_collision" in item.categories for item in run.candidates)


def test_npm_scoped_and_unscoped():
    service = AntiTyposquattingService()
    scoped = service.analyze(ProtectedAsset(AssetType.PACKAGE, "@example/acme-widget", PackageEcosystem.NPM), GenerationConfiguration(result_limit=100))
    assert any("namespace_confusion" in item.categories for item in scoped.candidates)
    assert service.analyze(ProtectedAsset(AssetType.PACKAGE, "acme-widget", PackageEcosystem.NPM)).candidates
    with pytest.raises(ValueError): service.analyze(ProtectedAsset(AssetType.PACKAGE, "Invalid Package", PackageEcosystem.NPM))


def test_exports_escape_html_and_csv_formula(tmp_path):
    run = domain_run()
    run.candidates[0].recommended_action = "=CMD()"
    json_path = export_json(run, tmp_path / "result.json")
    csv_path = export_csv(run, tmp_path / "result.csv")
    html_path = export_html(run, tmp_path / "result.html")
    docx_path = export_professional(run, tmp_path / "result.docx")
    xlsx_path = export_professional(run, tmp_path / "result.xlsx")
    assert json.loads(json_path.read_text())["schema_version"] == "1.0"
    rows = list(csv.DictReader(csv_path.open()))
    assert rows[0]["recommended_action"].startswith("'=")
    assert "<script" not in html_path.read_text().lower()
    assert docx_path.is_file() and xlsx_path.is_file()


def test_persistence_schema_and_parameterized_save(tmp_path):
    store = AntiTyposquattingStore(tmp_path / "analysis.sqlite3")
    run = domain_run()
    store.save_run(run, APP_VERSION)
    assert store.connection.execute("SELECT COUNT(*) FROM anti_typosquatting_candidates").fetchone()[0] == len(run.candidates)
    tables = {row[0] for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "anti_typosquatting_lookup_cache" in tables


def test_cli_offline_and_lookup_consent(capsys):
    assert cli_main(["analyze", "--asset-type", "domain", "--name", "examplebrand.test", "--offline", "--output", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == "1.0"
    assert cli_main(["analyze", "--asset-type", "domain", "--name", "examplebrand.test", "--lookup", "--output", "json"]) == 3
    assert json.loads(capsys.readouterr().err)["error_code"] == "CONSENT_REQUIRED"
    assert cli_main(["analyze", "--asset-type", "domain", "--name", "examplebrand.test", "--lookup", "--consent-live-lookup", "--output", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["candidates"][0]["lookup_status"] == "Registry Reservation or Policy Status Unknown"


def test_help_topic_registered():
    topic = get_topic("anti_typosquatting")
    assert topic and topic.title == "Anti-Typosquatting Protection"

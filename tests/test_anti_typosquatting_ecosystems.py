from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from mac_audit_agent.anti_typosquatting.investigation import EvidenceRecord, new_investigation
from mac_audit_agent.anti_typosquatting.models import AssetType, GenerationConfiguration, InvestigationStatus, PackageEcosystem, ProtectedAsset
from mac_audit_agent.anti_typosquatting.namespaces import adapter_for, matches_private, proxy_escape
from mac_audit_agent.anti_typosquatting.persistence import AntiTyposquattingStore
from mac_audit_agent.anti_typosquatting.project_audit import scan_project
from mac_audit_agent.anti_typosquatting.providers import GoModuleProvider
from mac_audit_agent.anti_typosquatting.service import AntiTyposquattingService


@pytest.mark.parametrize("ecosystem,name,key,component,projection", [
    (PackageEcosystem.CRATES_IO,"acme-widget","acme-widget","cargo_package","acme_widget"),
    (PackageEcosystem.RUBYGEMS,"acme-widget","acme-widget","gem","acme/widget"),
    (PackageEcosystem.NUGET,"Acme.Widget","acme.widget","package_id",""),
    (PackageEcosystem.MAVEN_CENTRAL,"com.example:acme-widget","com.example:acme-widget","group_id",""),
    (PackageEcosystem.GO_MODULE,"example.com/acme/widget/v2","example.com/acme/widget/v2","host",""),
    (PackageEcosystem.PACKAGIST,"example/acme-widget","example/acme-widget","vendor",""),
])
def test_namespace_parsing_and_generation(ecosystem,name,key,component,projection):
    parsed=adapter_for(ecosystem).parse_identifier(name)
    assert parsed.comparison_key == key
    assert component in {item.name for item in parsed.components}
    if projection: assert projection in parsed.projections
    run=AntiTyposquattingService().analyze(ProtectedAsset(AssetType.PACKAGE,name,ecosystem),GenerationConfiguration(result_limit=30))
    assert run.candidates and len(run.candidates)<=30
    assert all(item.ecosystem==ecosystem.value and item.normalized_name!=key for item in run.candidates if "normalization_collision" not in item.categories)


def test_registry_specific_collisions():
    service=AntiTyposquattingService()
    rust=service.analyze(ProtectedAsset(AssetType.PACKAGE,"acme-widget",PackageEcosystem.CRATES_IO),GenerationConfiguration(result_limit=100))
    assert any(any(r.rule_id=="CRATES.IMPORT_PROJECTION" for r in c.reasons) for c in rust.candidates)
    maven=service.analyze(ProtectedAsset(AssetType.PACKAGE,"com.example.security:acme-widget",PackageEcosystem.MAVEN_CENTRAL),GenerationConfiguration(result_limit=100))
    assert any(any(r.rule_id=="MAVEN.GROUP_SEGMENT_OMISSION" for r in c.reasons) for c in maven.candidates)
    go=service.analyze(ProtectedAsset(AssetType.PACKAGE,"example.com/acme/widget/v2",PackageEcosystem.GO_MODULE),GenerationConfiguration(result_limit=100))
    assert any(any(r.rule_id=="GO.SEMANTIC_MAJOR_OMISSION" for r in c.reasons) for c in go.candidates)


def test_nuget_case_is_same_identity():
    adapter=adapter_for(PackageEcosystem.NUGET)
    assert adapter.parse_identifier("Acme.Widget").comparison_key == adapter.parse_identifier("acme.widget").comparison_key


def test_go_privacy_and_proxy_escape(monkeypatch):
    assert matches_private("corp.example/internal/widget","corp.example/*")
    assert proxy_escape("Example.com/Widget") == "!example.com/!widget"
    monkeypatch.setattr("urllib.request.urlopen",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("network leak")))
    result=GoModuleProvider().lookup("corp.example/internal/widget",private_patterns="corp.example/*")
    assert result.evidence["redacted_module"] == "<private-module>"


def test_investigation_human_and_authoritative_gates():
    case=new_investigation()
    case.transition(InvestigationStatus.SUSPICIOUS,actor="engine",rationale="multiple signals",human=False)
    with pytest.raises(PermissionError): case.transition(InvestigationStatus.CONFIRMED,actor="engine",rationale="similar",human=False)
    with pytest.raises(ValueError): case.transition(InvestigationStatus.CONFIRMED,actor="reviewer",rationale="similar",human=True)
    case.evidence.append(EvidenceRecord("registry_enforcement","registry","ticket-1","authoritative","abc","2026-01-01T00:00:00Z"))
    case.transition(InvestigationStatus.CONFIRMED,actor="reviewer",rationale="Registry enforcement ticket verified.",human=True)
    assert case.status == InvestigationStatus.CONFIRMED and len(case.audit_log)==2


def test_v1_database_migrates_without_data_loss(tmp_path):
    path=tmp_path/"old.sqlite3"; db=sqlite3.connect(path)
    db.executescript("CREATE TABLE anti_typosquatting_schema(version INTEGER NOT NULL); INSERT INTO anti_typosquatting_schema VALUES(1); CREATE TABLE protected_assets(id INTEGER PRIMARY KEY,asset_type TEXT,ecosystem TEXT DEFAULT '',canonical_name TEXT,normalized_name TEXT,display_name TEXT,owner_label TEXT DEFAULT '',business_criticality INTEGER DEFAULT 50,created_at TEXT,updated_at TEXT,UNIQUE(asset_type,ecosystem,normalized_name)); INSERT INTO protected_assets(asset_type,ecosystem,canonical_name,normalized_name,display_name,created_at,updated_at) VALUES('package','npm','acme-widget','acme-widget','acme-widget','now','now');")
    db.commit(); db.close()
    store=AntiTyposquattingStore(path)
    assert store.connection.execute("SELECT version FROM anti_typosquatting_schema").fetchone()[0]==3
    assert store.connection.execute("SELECT canonical_name FROM protected_assets").fetchone()[0]=="acme-widget"
    assert store.connection.execute("SELECT name FROM sqlite_master WHERE name='anti_typosquatting_investigations'").fetchone()


def test_v2_database_additive_migration_is_restart_safe(tmp_path):
    path=tmp_path/"v2.sqlite3"
    first=AntiTyposquattingStore(path)
    first.connection.execute("UPDATE anti_typosquatting_schema SET version=2")
    first.connection.commit(); first.connection.close()
    migrated=AntiTyposquattingStore(path)
    assert migrated.connection.execute("SELECT version FROM anti_typosquatting_schema").fetchone()[0]==3
    columns={row[1] for row in migrated.connection.execute("PRAGMA table_info(protected_assets)")}
    assert {"identifier_components_json","product_family","visibility","lifecycle_state"} <= columns
    migrated.connection.close()
    assert AntiTyposquattingStore(path).connection.execute("SELECT version FROM anti_typosquatting_schema").fetchone()[0]==3


def test_local_project_audit_all_core_ecosystems(tmp_path):
    (tmp_path/"package.json").write_text(json.dumps({"dependencies":{"acme-wdiget":"1.0.0"}}))
    (tmp_path/"pyproject.toml").write_text('[project]\ndependencies=["acme-wdiget>=1"]\n')
    (tmp_path/"Cargo.toml").write_text('[dependencies]\nacme-wdiget="1"\n')
    (tmp_path/"Gemfile").write_text("gem 'acme-wdiget'\n")
    (tmp_path/"packages.config").write_text('<packages><package id="Acme.Wdiget" version="1" /></packages>')
    (tmp_path/"pom.xml").write_text('<project><dependencies><dependency><groupId>com.example</groupId><artifactId>acme-wdiget</artifactId></dependency></dependencies></project>')
    (tmp_path/"go.mod").write_text('module example.com/app\nrequire example.com/acme/wdiget v1.0.0\n')
    (tmp_path/"composer.json").write_text(json.dumps({"require":{"example/acme-wdiget":"1.0"}}))
    report=scan_project(tmp_path)
    assert {item.ecosystem for item in report.occurrences} >= set(PackageEcosystem)
    assert report.files_scanned==8


def test_project_audit_detects_near_match_without_network(tmp_path,monkeypatch):
    (tmp_path/"package.json").write_text(json.dumps({"dependencies":{"acme-wdiget":"1.0.0"}}))
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k: (_ for _ in ()).throw(AssertionError("network")))
    asset=ProtectedAsset(AssetType.PACKAGE,"acme-widget",PackageEcosystem.NPM)
    report=scan_project(tmp_path,[asset])
    assert report.findings and report.findings[0]["supply_chain_reachability"]==80


def test_symlink_outside_root_is_not_followed(tmp_path):
    outside=tmp_path.parent/"outside-package.json"; outside.write_text('{"dependencies":{"bad":"1"}}')
    (tmp_path/"package.json").symlink_to(outside)
    assert scan_project(tmp_path).occurrences == []

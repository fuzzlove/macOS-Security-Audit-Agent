from __future__ import annotations

import io
import json
import zipfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from mac_audit_agent.threat_definitions import sources as source_module
from mac_audit_agent.threat_definitions.manager import ThreatIntelligenceManager, default_registry
from mac_audit_agent.threat_definitions.lifecycle import apply_default_expiration, evaluate_lifecycle
from mac_audit_agent.threat_definitions.matcher import DefinitionMatcher
from mac_audit_agent.threat_definitions.models import (
    DefinitionAction, DefinitionProvenance, DefinitionType, RawDefinitionPackage,
    SourcePolicy, ThreatDefinition, TrustClass, utc_now,
)
from mac_audit_agent.threat_definitions.normalization import NormalizationError, definition_id, normalize_value
from mac_audit_agent.threat_definitions.signing import ManifestSigner, ManifestTrustStore
from mac_audit_agent.threat_definitions.sources import (
    ABUSE_CH_AUTH_ENV, CISAKEVAdapter, MalwareBazaarAdapter, SignedBundleAdapter,
    SourceRegistry, ThreatFoxAdapter, URLhausAdapter,
)
from mac_audit_agent.threat_definitions.store import BundleError, DefinitionStore
from mac_audit_agent.threat_definitions.validation import DefinitionValidator, deduplicate


def _definition(kind: DefinitionType = DefinitionType.DOMAIN, value: str = "evil.example", *, source: str = "test", group: str | None = None, action: DefinitionAction = DefinitionAction.CORRELATE, trust: TrustClass = TrustClass.TRUSTED) -> ThreatDefinition:
    canonical = normalize_value(kind, value)
    return ThreatDefinition(
        definition_id(kind, canonical), kind, canonical, confidence=0.8, action=action,
        provenance=(DefinitionProvenance(source, source_confidence=0.8, trust_class=trust, dependency_group=group or source),),
    )


def _signed_store(root: Path) -> tuple[DefinitionStore, ManifestSigner]:
    key = Ed25519PrivateKey.generate()
    trust = root / "trusted_keys"
    trust.mkdir(parents=True)
    (trust / "release-1.pem").write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    return DefinitionStore(root, trust_store=ManifestTrustStore(trust)), ManifestSigner("release-1", key.sign)


def test_indicator_normalization_is_typed_and_does_not_broaden_scope():
    assert normalize_value(DefinitionType.DOMAIN, "Exämple.COM.") == "xn--exmple-cua.com"
    assert normalize_value(DefinitionType.IPV6, "2001:0db8::1") == "2001:db8::1"
    assert normalize_value(DefinitionType.CIDR, "192.0.2.7/24") == "192.0.2.0/24"
    assert normalize_value(DefinitionType.URL, "HTTPS://Example.COM:443/a?q=1#fragment") == "https://example.com/a?q=1"
    with pytest.raises(NormalizationError):
        normalize_value(DefinitionType.DOMAIN, "*.example.com")
    with pytest.raises(NormalizationError):
        normalize_value(DefinitionType.SHA256, "abc")


def test_threatfox_preserves_provenance_and_defaults_to_correlation():
    payload = {"data": [{"id": "42", "ioc": "Bad.Example.", "ioc_type": "domain", "malware_printable": "ExampleFamily", "confidence_level": 75, "tags": ["c2"]}]}
    adapter = ThreatFoxAdapter(url="https://example.invalid/feed", enabled=True, fetcher=lambda *_: (b"", "", {}))
    definitions = adapter.parse(RawDefinitionPackage("threatfox", json.dumps(payload).encode(), source_reference="fixture"))
    assert len(definitions) == 1
    assert definitions[0].value == "bad.example"
    assert definitions[0].action == DefinitionAction.CORRELATE
    assert definitions[0].provenance[0].source_id == "threatfox"


def test_provider_auth_key_path_is_redacted_from_package_provenance():
    adapter = ThreatFoxAdapter(
        url="https://threatfox-api.abuse.ch/v2/files/exports/sensitive-key/recent.json",
        enabled=True,
        fetcher=lambda *_: (b'{"data": []}', "application/json", {}),
    )
    package = adapter.download()
    assert "sensitive-key" not in str(package.source_reference)
    assert "REDACTED" in str(package.source_reference)


def test_urlhaus_commented_csv_header_is_parsed_without_becoming_data():
    payload = b'# generated\n# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n1,"2026-08-25 10:00:00",http://bad.example/a,online,malware_download,elf,ref,analyst\n'
    adapter = URLhausAdapter(url="https://example.invalid/feed", enabled=True, fetcher=lambda *_: (b"", "", {}))
    definitions = adapter.parse(RawDefinitionPackage("urlhaus", payload, source_reference="fixture"))
    assert len(definitions) == 1
    assert definitions[0].value == "http://bad.example/a"


def test_cisa_kev_public_adapter_preserves_ransomware_and_remediation_context():
    payload = {
        "vulnerabilities": [{
            "cveID": "CVE-2026-12345", "vendorProject": "Example", "product": "Agent",
            "vulnerabilityName": "Example vulnerability", "dateAdded": "2026-08-25",
            "requiredAction": "Apply the vendor update", "dueDate": "2026-09-01",
            "knownRansomwareCampaignUse": "Known",
        }],
    }
    adapter = CISAKEVAdapter(enabled=True, fetcher=lambda *_: (b"", "", {}))
    definitions = adapter.parse(RawDefinitionPackage("cisa_kev", json.dumps(payload).encode(), source_reference="fixture"))
    assert len(definitions) == 1
    definition = definitions[0]
    assert definition.definition_type == DefinitionType.IOC
    assert definition.value == "CVE-2026-12345"
    assert definition.action == DefinitionAction.CORRELATE
    assert "known-ransomware-use" in definition.tags
    assert definition.metadata["required_action"] == "Apply the vendor update"
    assert definition.provenance[0].trust_class == TrustClass.AUTHORITATIVE


def test_default_registry_enables_anonymous_and_free_setup_community_sources():
    policies = {adapter.source_id: adapter.policy for adapter in default_registry().all()}
    assert policies["cisa_kev"].enabled is True
    assert policies["cisa_kev"].commercial_use_status == "PUBLIC_SOURCE_NO_ACCEPTANCE_REQUIRED"
    assert policies["yara_forge"].enabled is True
    assert policies["threatfox"].enabled is True
    assert policies["urlhaus"].enabled is True
    assert policies["malwarebazaar"].enabled is True
    assert policies["msaa_signed_bundle"].enabled is False

    explicit = {adapter.source_id: adapter.policy.enabled for adapter in default_registry(enabled_sources={"yara_forge"}).all()}
    assert explicit["yara_forge"] is True
    assert explicit["cisa_kev"] is False


def test_abuse_ch_sources_report_free_setup_and_never_expose_key(monkeypatch):
    monkeypatch.delenv(ABUSE_CH_AUTH_ENV, raising=False)
    monkeypatch.setattr(source_module, "load_abuse_ch_auth_key", lambda: "")
    adapters = {adapter.source_id: adapter for adapter in default_registry().all()}
    assert adapters["threatfox"].setup_requirement()["status"] == "SETUP_REQUIRED_FREE"
    assert adapters["urlhaus"].setup_requirement()["setup_url"] == "https://auth.abuse.ch/"
    assert adapters["malwarebazaar"].setup_requirement()["status"] == "SETUP_REQUIRED_FREE"

    secret = "A" * 48
    monkeypatch.setenv(ABUSE_CH_AUTH_ENV, secret)
    monkeypatch.setattr(source_module, "load_abuse_ch_auth_key", lambda: secret)
    captured = {}

    def fetcher(url, _maximum, _headers):
        captured["url"] = url
        return b'{"data": []}', "application/json", {}

    adapter = ThreatFoxAdapter(
        url="https://threatfox-api.abuse.ch/v2/files/exports/AUTH-KEY-REQUIRED/recent.json",
        enabled=True,
        fetcher=fetcher,
    )
    package = adapter.download()
    assert secret in captured["url"]
    assert secret not in str(package.source_reference)
    assert "REDACTED" in str(package.source_reference)


def test_malwarebazaar_uses_authenticated_metadata_post_not_sample_download(monkeypatch):
    secret = "B" * 48
    monkeypatch.setenv(ABUSE_CH_AUTH_ENV, secret)
    captured = {}

    def post_fetcher(url, maximum, form, headers):
        captured.update(url=url, maximum=maximum, form=form, headers=headers)
        return b'{"query_status":"ok","data":[]}', "application/json", {}

    adapter = MalwareBazaarAdapter(
        url="https://mb-api.abuse.ch/api/v1/", enabled=True, post_fetcher=post_fetcher,
    )
    package = adapter.download()
    assert captured["form"] == {"query": "get_recent", "selector": "100"}
    assert captured["headers"] == {"Auth-Key": secret}
    assert secret not in str(package.source_reference)


def test_deduplication_correlates_independent_sources_but_not_feed_mirrors():
    first = _definition(source="one", group="shared")
    mirror = _definition(source="two", group="shared")
    independent = _definition(source="three", group="independent")
    shared, _ = deduplicate((first, mirror))
    corroborated, _ = deduplicate((first, mirror, independent))
    assert len(shared) == len(corroborated) == 1
    assert corroborated[0].confidence > shared[0].confidence
    assert len(corroborated[0].provenance) == 3


def test_external_block_request_is_not_automatic_prevention():
    item = _definition(action=DefinitionAction.BLOCK, trust=TrustClass.TRUSTED)
    merged, _ = deduplicate((item,))
    assert merged[0].action == DefinitionAction.ALERT
    assert merged[0].metadata["requested_action"] == "BLOCK"


def test_allowlist_conflict_retains_detection_visibility():
    allow = _definition(DefinitionType.ALLOWLIST, "evil.example", source="admin", trust=TrustClass.LOCAL_ADMIN)
    deny = _definition(DefinitionType.DOMAIN, "evil.example")
    merged, conflicts = deduplicate((allow, deny))
    assert len(merged) == 2
    assert conflicts[0]["code"] == "ALLOWLIST_POLICY_CONFLICT"


def test_empty_feed_and_suspicious_reduction_are_rejected():
    policy = SourcePolicy("fixture", "Fixture", TrustClass.TRUSTED, 0.8, True, expected_minimum_count=10, maximum_reduction_fraction=0.5)
    assert not DefinitionValidator.validate_delta(100, 0, policy).accepted
    assert not DefinitionValidator.validate_delta(100, 20, policy).accepted
    assert DefinitionValidator.validate_delta(100, 80, policy).accepted


def test_signed_bundle_activation_and_tamper_detection(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    store.stage("2026.08.25.1", [_definition()], signer=signer)
    result = store.activate("2026.08.25.1", reload_callback=lambda _: True)
    assert result["status"] == "ACTIVATED"
    assert store.definitions()[0].value == "evil.example"
    active = store.active_bundle_path()
    assert active is not None
    (active / "definitions.jsonl").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(BundleError, match="integrity mismatch"):
        store.definitions()


def test_empty_bundle_is_rejected_before_staging(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    with pytest.raises(BundleError, match="empty"):
        store.stage("2026.08.25.1", [], signer=signer)


def test_failed_sensor_reload_restores_previous_active_pointer(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    store.stage("2026.08.25.1", [_definition()], signer=signer)
    store.activate("2026.08.25.1")
    store.stage("2026.08.25.2", [_definition(DefinitionType.SHA256, "a" * 64)], signer=signer)
    with pytest.raises(BundleError, match="rolled back"):
        store.activate("2026.08.25.2", reload_callback=lambda _: False)
    assert store.active_bundle_path().name == "2026.08.25.1"


def test_last_known_good_rollback_is_explicit_and_verified(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    store.stage("2026.08.25.1", [_definition()], signer=signer)
    store.activate("2026.08.25.1")
    store.stage("2026.08.25.2", [_definition(DefinitionType.SHA256, "b" * 64)], signer=signer)
    store.activate("2026.08.25.2")
    result = store.rollback(reload_callback=lambda _: True)
    assert result["version"] == "2026.08.25.1"


def test_signed_offline_export_import_uses_same_validation(tmp_path: Path):
    source, signer = _signed_store(tmp_path / "source")
    source.stage("2026.08.25.1", [_definition()], signer=signer)
    source.activate("2026.08.25.1")
    archive = source.export_bundle("2026.08.25.1", tmp_path / "definitions.bundle")
    destination = tmp_path / "destination"
    trust = destination / "trusted_keys"
    trust.mkdir(parents=True)
    shutil_key = (tmp_path / "source" / "trusted_keys" / "release-1.pem").read_bytes()
    (trust / "release-1.pem").write_bytes(shutil_key)
    imported = DefinitionStore(destination, trust_store=ManifestTrustStore(trust)).import_bundle(archive)
    assert imported["status"] == "STAGED"


def test_offline_import_rejects_path_traversal(tmp_path: Path):
    store = DefinitionStore(tmp_path / "definitions")
    archive = tmp_path / "bad.bundle"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape", "bad")
    with pytest.raises(BundleError, match="unsafe path"):
        store.import_bundle(archive)
    assert not (tmp_path / "escape").exists()


def test_missing_offline_bundle_reports_exact_path_without_generic_startup_error(tmp_path: Path, capsys):
    from mac_audit_agent.threat_definitions.cli import main

    missing = tmp_path / "not-present.bundle"
    result = main(["import", str(missing), "--root", str(tmp_path / "definitions"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert result == 2
    assert payload["error_code"] == "DEF_IMPORT_REJECTED"
    assert str(missing) in payload["message"]
    assert payload["active_definitions_unchanged"] is True


class _FixtureAdapter:
    source_id = "fixture"
    policy = SourcePolicy("fixture", "Fixture", TrustClass.LOCAL_ADMIN, 0.9, True, expected_minimum_count=1)

    def check_for_updates(self):
        raise NotImplementedError

    def download(self):
        return RawDefinitionPackage("fixture", b"fixture", metadata={"etag": "v1"})

    def parse(self, package):
        return [_definition(source="fixture", trust=TrustClass.LOCAL_ADMIN)]


class _CombinedFixtureAdapter:
    def __init__(self, source_id: str, definitions: list[ThreatDefinition]):
        self.source_id = source_id
        self.definitions = definitions
        self.policy = SourcePolicy(
            source_id, source_id.title(), TrustClass.LOCAL_ADMIN, 0.9, True,
            expected_minimum_count=1, minimum_interval_seconds=0,
        )

    def check_for_updates(self):
        raise NotImplementedError

    def download(self):
        return RawDefinitionPackage(self.source_id, b"fixture", metadata={"etag": f"{self.source_id}-v1"})

    def parse(self, package):
        return self.definitions


def test_manager_source_update_stages_then_activates_signed_bundle(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    registry = SourceRegistry()
    registry.register(_FixtureAdapter())
    manager = ThreatIntelligenceManager(store, registry=registry)
    result = manager.update_source("fixture", signer=signer, version="2026.08.25.1")
    assert result["status"] == "STAGED"
    manager.activate("2026.08.25.1")
    assert manager.status()["state"] == "HEALTHY"


def test_enabled_sources_compile_into_one_deduplicated_knowledge_bundle(tmp_path: Path):
    shared_one = _definition(source="source_one", group="independent_one")
    shared_two = _definition(source="source_two", group="independent_two")
    md5 = _definition(DefinitionType.MD5, "a" * 32, source="source_two", trust=TrustClass.LOCAL_ADMIN)
    registry = SourceRegistry()
    registry.register(_CombinedFixtureAdapter("source_one", [shared_one]))
    registry.register(_CombinedFixtureAdapter("source_two", [shared_two, md5]))
    store = DefinitionStore(tmp_path / "definitions", require_signatures=False)
    manager = ThreatIntelligenceManager(store, registry=registry)

    result = manager.update_enabled()

    assert result["_compilation"]["status"] == "STAGED"
    assert result["_compilation"]["contributing_sources"] == ["source_one", "source_two"]
    assert result["source_one"]["version"] == result["source_two"]["version"]
    compiled = store.definitions(result["_compilation"]["version"])
    assert len(compiled) == 2
    domain = next(item for item in compiled if item.definition_type == DefinitionType.DOMAIN)
    assert {item.source_id for item in domain.provenance} == {"source_one", "source_two"}
    assert domain.confidence > shared_one.confidence
    assert next(item for item in compiled if item.definition_type == DefinitionType.MD5).value == "a" * 32


def test_failed_source_does_not_discard_other_validated_source(tmp_path: Path):
    class BrokenAdapter(_CombinedFixtureAdapter):
        def download(self):
            raise RuntimeError("fixture unavailable")

    registry = SourceRegistry()
    registry.register(BrokenAdapter("broken", [_definition(source="broken")]))
    registry.register(_CombinedFixtureAdapter("healthy", [_definition(source="healthy")]))
    store = DefinitionStore(tmp_path / "definitions", require_signatures=False)
    manager = ThreatIntelligenceManager(store, registry=registry)

    result = manager.update_enabled()

    assert result["broken"]["status"] == "FAILED"
    assert result["healthy"]["status"] == "STAGED"
    assert result["_compilation"]["contributing_sources"] == ["healthy"]


def test_stale_definitions_remain_active_with_explicit_degradation(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    store.stage("2026.08.25.1", [_definition()], signer=signer)
    store.activate("2026.08.25.1")
    pointer = store._pointer(store.active_dir)
    pointer["activated_at"] = (utc_now() - timedelta(days=31)).isoformat()
    store._atomic_json(store.active_dir / "current.json", pointer)
    status = ThreatIntelligenceManager(store).status()
    assert status["state"] == "DEGRADED"
    assert status["freshness"] == "VERY_STALE"
    assert status["definition_count"] == 1


def test_unprivileged_status_uses_sanitized_privileged_cache(tmp_path: Path, monkeypatch):
    cache = tmp_path / "threat-definitions-status.json"
    cached = {
        "schema_version": "1.0", "state": "HEALTHY", "freshness": "CURRENT",
        "active_version": "2026.08.25.1", "definition_count": 12,
        "counts_by_type": {"DOMAIN": 12}, "sources": [], "previous_version": None,
    }
    cache.write_text(json.dumps(cached), encoding="utf-8")
    manager = ThreatIntelligenceManager(
        DefinitionStore(tmp_path / "restricted"), status_cache_path=cache,
    )
    monkeypatch.setattr(manager, "_direct_status", lambda: (_ for _ in ()).throw(PermissionError("restricted")))
    status = manager.status()
    assert status["state"] == "HEALTHY"
    assert status["status_source"] == "privileged_sanitized_cache"


def test_unprivileged_status_without_cache_is_explicit_not_exception(tmp_path: Path, monkeypatch):
    manager = ThreatIntelligenceManager(
        DefinitionStore(tmp_path / "restricted"), status_cache_path=tmp_path / "missing.json",
    )
    monkeypatch.setattr(manager, "_direct_status", lambda: (_ for _ in ()).throw(PermissionError("restricted")))
    status = manager.status()
    assert status["state"] == "PERMISSION_BLOCKED"
    assert status["status_source"] == "permission_fallback"


def test_privileged_status_cache_omits_provider_errors_and_policy(tmp_path: Path):
    cache = tmp_path / "public-status.json"
    manager = ThreatIntelligenceManager(
        DefinitionStore(tmp_path / "definitions"), status_cache_path=cache,
    )
    manager._write_status_cache({
        "state": "DEGRADED", "freshness": "STALE", "definition_count": 2,
        "counts_by_type": {"DOMAIN": 2}, "validation_state": "VALID",
        "sources": [{
            "source_id": "fixture", "state": "FAILED", "enabled": True,
            "definition_count": 2, "error": "https://feed.invalid/?token=secret",
            "policy": {"terms_reference": "/private/provider/config"},
        }],
    })
    document = json.loads(cache.read_text(encoding="utf-8"))
    assert document["sources"][0]["source_id"] == "fixture"
    assert "error" not in document["sources"][0]
    assert "policy" not in document["sources"][0]
    assert "secret" not in cache.read_text(encoding="utf-8")


def test_broken_yara_rule_never_passes_activation_validation():
    item = _definition(DefinitionType.YARA_RULE, "rule broken { condition: }")
    result = DefinitionValidator().validate([item])
    assert not result.accepted
    assert any(issue.code in {"YARA_COMPILATION_FAILED", "YARA_DEPENDENCY_MISSING"} for issue in result.issues)


def test_type_specific_lifecycle_ages_shared_ips_before_file_hashes():
    ip = apply_default_expiration(_definition(DefinitionType.IPV4, "192.0.2.1"))
    digest = apply_default_expiration(_definition(DefinitionType.SHA256, "c" * 64))
    assert ip.expires_at is not None and digest.expires_at is not None
    assert digest.expires_at > ip.expires_at
    expired = evaluate_lifecycle(replace(ip, expires_at=utc_now() - timedelta(seconds=1)))
    assert expired.lifecycle.value == "EXPIRED"


def test_matcher_supports_cidr_and_allowlist_conflict_without_suppressing_detection():
    cidr = _definition(DefinitionType.CIDR, "192.0.2.0/24", action=DefinitionAction.ALERT)
    allow = _definition(DefinitionType.ALLOWLIST, "192.0.2.7", source="admin", trust=TrustClass.LOCAL_ADMIN)
    blocked = _definition(DefinitionType.IPV4, "192.0.2.7", source="admin", action=DefinitionAction.BLOCK, trust=TrustClass.LOCAL_ADMIN)
    match = DefinitionMatcher((cidr, allow, blocked)).match(DefinitionType.IPV4, "192.0.2.7")
    assert match.matched and match.policy_conflict
    assert match.action == DefinitionAction.ALERT
    assert len(match.definition_ids) == 2


def test_versioned_behavior_rule_requires_operational_schema():
    invalid = _definition(DefinitionType.BEHAVIOR_RULE, json.dumps({"description": "missing fields"}))
    assert not DefinitionValidator().validate([invalid], run_yara_gate=False).accepted
    document = {
        "rule_id": "suspicious_launchdaemon", "version": "1", "description": "Unexpected LaunchDaemon",
        "severity": "HIGH", "confidence": 0.8, "required_telemetry": ["file_modification"],
        "conditions": {"path_prefix": "/Library/LaunchDaemons"}, "exclusions": [],
        "mitre_attack": ["T1543.004"], "recommended_response": "Review signer and parent process.",
    }
    valid = _definition(DefinitionType.BEHAVIOR_RULE, json.dumps(document))
    assert DefinitionValidator().validate([valid], run_yara_gate=False).accepted


@pytest.mark.parametrize("suffix", [".html", ".docx", ".xlsx", ".json"])
def test_definition_diagnostics_export_all_required_formats(tmp_path: Path, suffix: str):
    from mac_audit_agent.threat_definitions.diagnostics import export_diagnostics

    manager = ThreatIntelligenceManager(DefinitionStore(tmp_path / "definitions", require_signatures=False))
    output = export_diagnostics(manager, tmp_path / f"definition-health{suffix}")
    assert output.is_file() and output.stat().st_size > 0


def test_bundle_contains_typed_sensor_indexes(tmp_path: Path):
    store, signer = _signed_store(tmp_path / "definitions")
    manifest = store.stage("2026.08.25.1", [_definition(), _definition(DefinitionType.SHA256, "d" * 64)], signer=signer)
    assert "domains/domain.jsonl" in manifest["files"]
    assert "hashes/sha256.jsonl" in manifest["files"]


def test_connected_endpoint_activates_prebuilt_signed_release_without_private_key(tmp_path: Path):
    release_store, signer = _signed_store(tmp_path / "release")
    release_store.stage("2026.08.25.1", [_definition()], signer=signer)
    release_store.activate("2026.08.25.1")
    archive = release_store.export_bundle("2026.08.25.1", tmp_path / "release.bundle")

    endpoint_root = tmp_path / "endpoint"
    trust = endpoint_root / "trusted_keys"
    trust.mkdir(parents=True)
    (trust / "release-1.pem").write_bytes((tmp_path / "release" / "trusted_keys" / "release-1.pem").read_bytes())
    adapter = SignedBundleAdapter(url="https://updates.example/definitions.bundle", enabled=True, fetcher=lambda *_: (archive.read_bytes(), "application/zip", {"etag": "release-1"}))
    registry = SourceRegistry()
    registry.register(adapter)
    manager = ThreatIntelligenceManager(DefinitionStore(endpoint_root, trust_store=ManifestTrustStore(trust)), registry=registry)
    result = manager.update_source("msaa_signed_bundle", activate=True)
    assert result["status"] == "ACTIVE"
    assert manager.status()["active_version"] == "2026.08.25.1"

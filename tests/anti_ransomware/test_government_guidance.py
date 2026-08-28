from __future__ import annotations

import json
from pathlib import Path

import pytest

from mac_audit_agent.anti_ransomware.guidance_engine import GuidanceEngine
from mac_audit_agent.anti_ransomware.knowledge import load_knowledge_bundle, resource_root, verify_resource_integrity
from mac_audit_agent.anti_ransomware.reports import build_report
from mac_audit_agent.ui.anti_ransomware_panel import open_government_url_in_new_window


def test_offline_knowledge_bundle_loads_and_verifies() -> None:
    bundle = load_knowledge_bundle()

    assert bundle.references
    assert verify_resource_integrity()
    assert all(item["url"].startswith("https://") for item in bundle.references)
    assert bundle.versions["government_references.json"]


def test_guidance_maps_encryption_detection_to_official_response() -> None:
    guidance = GuidanceEngine().resolve(
        {"detection_type": "encryption_burst", "severity": "critical", "confidence": "high"}
    )

    assert guidance.severity == "critical"
    assert any(item["technique_id"] == "T1486" for item in guidance.mitre_techniques)
    assert any(item["organization"] == "CISA" for item in guidance.government_guidance)
    assert any("Isolate" in action for action in guidance.recommended_actions)
    assert guidance.offline is True


def test_invalid_or_insecure_reference_url_is_rejected(tmp_path: Path) -> None:
    for source in resource_root().iterdir():
        if source.is_file():
            (tmp_path / source.name).write_bytes(source.read_bytes())
    payload_path = tmp_path / "government_references.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["references"][0]["url"] = "http://example.invalid/ransomware"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="official reference must use HTTPS"):
        load_knowledge_bundle(tmp_path, verify_integrity=False)


def test_report_contains_guidance_without_network_access() -> None:
    report = build_report(
        assessment={"severity": "critical", "confidence": "high"},
        behaviors=["encryption_burst"],
        evidence={},
    )

    assert report["government_guidance"]
    assert report["government_guidance"][0]["offline"] is True
    assert report["government_guidance"][0]["recommended_actions"]


def test_government_resource_opens_with_macos_new_window_flag(monkeypatch) -> None:
    calls=[]
    monkeypatch.setattr("mac_audit_agent.ui.anti_ransomware_panel.subprocess.Popen",lambda args,**kwargs:calls.append((args,kwargs)) or object())
    assert open_government_url_in_new_window("https://www.cisa.gov/stopransomware") is True
    assert calls[0][0]==["/usr/bin/open","-n","https://www.cisa.gov/stopransomware"]


@pytest.mark.parametrize("url",["http://www.cisa.gov/stopransomware","https://cisa.gov.evil.example/resource","javascript:alert(1)"])
def test_government_resource_rejects_untrusted_url(url,monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.ui.anti_ransomware_panel.subprocess.Popen",lambda *args,**kwargs:pytest.fail("untrusted URL was launched"))
    assert open_government_url_in_new_window(url) is False

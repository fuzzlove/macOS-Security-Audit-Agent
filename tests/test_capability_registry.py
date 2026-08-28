from __future__ import annotations

from mac_audit_agent.runtime.capabilities import CAPABILITY_SPECS, CapabilityRegistry


def test_all_required_capabilities_are_classified() -> None:
    summary = CapabilityRegistry().summary()
    required = {"core_cli", "doctor", "gui", "user_notifier", "active_protection_install", "network_scan_basic", "network_scan_enhanced", "docx_export", "xlsx_export", "pdf_export", "packet_capture"}
    assert required <= set(summary)
    assert all(item["status"] in {"available", "degraded", "unavailable", "blocked"} for item in summary.values())
    assert set(summary) == set(CAPABILITY_SPECS)


def test_missing_optional_dependency_degrades_only_its_capability(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.runtime.capabilities._module", lambda name: False if name == "openpyxl" else True)
    registry = CapabilityRegistry()
    assert registry.evaluate("xlsx_export").status == "degraded"
    assert registry.evaluate("json_export").status == "available"

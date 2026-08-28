from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication, QDialog
import pytest

from mac_audit_agent.apple_exposure_guidance import (
    build_apple_exposure_update_guide,
    is_meaningful_value,
    normalize_apple_exposure_item,
)
from mac_audit_agent.apple_exposure_guidance_validation import validate_apple_exposure_payload


def test_is_meaningful_value_handles_nested_values() -> None:
    assert is_meaningful_value(None) is False
    assert is_meaningful_value("") is False
    assert is_meaningful_value("   ") is False
    assert is_meaningful_value([]) is False
    assert is_meaningful_value({}) is False
    assert is_meaningful_value(["", None, []]) is False
    assert is_meaningful_value(["CVE-2025-1234"]) is True
    assert is_meaningful_value(False) is True
    assert is_meaningful_value(0) is True


def test_normalize_payload_with_empty_list_does_not_crash() -> None:
    payload = normalize_apple_exposure_item({"alerts": [{"title": "Apple item"}], "cves": []})
    assert payload["normalized_cves"] == []


def test_normalize_payload_with_nonempty_list_retained() -> None:
    payload = normalize_apple_exposure_item({"alerts": [{"title": "Apple item"}], "cves": ["CVE-2025-1234"]})
    assert payload["cves"] == ["CVE-2025-1234"]
    assert payload["normalized_cves"] == ["CVE-2025-1234"]


def test_normalize_payload_with_nested_dict_retained() -> None:
    payload = normalize_apple_exposure_item({"alerts": [{"title": "Apple item"}], "nvd": {"cvss": "high"}})
    assert payload["nvd"] == {"cvss": "high"}


def test_normalize_payload_with_empty_nested_values() -> None:
    payload = normalize_apple_exposure_item({"alerts": [{"title": "Apple item"}], "references": ["", None, []]})
    assert "references" not in payload or payload["references"] == ["", None, []]
    assert payload["normalized_cves"] == []


def test_false_and_zero_values_are_not_dropped() -> None:
    payload = normalize_apple_exposure_item({"alerts": [{"title": "Apple item"}], "known_exploited": False, "cvss_score": 0})
    assert payload["known_exploited"] is False
    assert payload["cvss_score"] == 0


def test_build_update_guide_multiple_cves() -> None:
    guide = build_apple_exposure_update_guide({"title": "macOS update", "cves": ["CVE-2025-1111", "CVE-2025-2222"]})
    text = guide.to_text()
    assert "CVE-2025-1111" in text
    assert "CVE-2025-2222" in text


def test_build_update_guide_no_cve() -> None:
    guide = build_apple_exposure_update_guide({"title": "macOS update"})
    text = guide.to_text()
    assert "No CVE was associated with this finding" in text
    assert "CVE-2025" not in text


def test_build_update_guide_with_kev_context() -> None:
    guide = build_apple_exposure_update_guide({"title": "Known exploited WebKit", "kev": True, "forecast_level": "critical", "cves": ["CVE-2025-9999"]})
    text = guide.to_text()
    assert guide.title == "Known Exploited Apple Vulnerability Guidance"
    assert "Known exploited status" in text
    assert "CVE-2025-9999" in text


def test_payload_validation_allows_structured_values() -> None:
    result = validate_apple_exposure_payload({"title": "Item", "references": [{"url": "https://example.test"}], "extra": {"nested": ["value"]}})
    assert result.valid is True
    assert "extra" in result.extra_metadata
    assert "references" in result.unsafe_types


def test_open_card_update_guidance_handles_exception(monkeypatch) -> None:
    from mac_audit_agent.runtime.python_compat import current_python_gui_compatibility

    if not current_python_gui_compatibility().supported_for_gui:
        pytest.skip("Qt GUI tests are skipped on unsupported Python GUI runtime.")
    from mac_audit_agent.ui import cve_radar_panel

    app = QApplication.instance() or QApplication([])
    panel = cve_radar_panel.CveRadarPanel()
    captured: list[str] = []

    def fail(*_args, **_kwargs):
        raise TypeError("cannot use 'list' as a set element")

    def fake_init(self, body, diagnostics, parent=None):
        captured.append(body)
        captured.append(diagnostics["error_type"])
        QDialog.__init__(self, parent)

    monkeypatch.setattr(cve_radar_panel, "build_apple_exposure_update_guide", fail)
    monkeypatch.setattr(cve_radar_panel.CveRadarUpdateGuidanceErrorDialog, "__init__", fake_init)
    monkeypatch.setattr(cve_radar_panel.CveRadarUpdateGuidanceErrorDialog, "exec", lambda self: 0)
    panel._open_card_update_guidance({"title": "Broken card", "cves": []})
    assert "Update guidance could not be generated for this item." in captured[0]
    assert captured[1] == "TypeError"
    panel.close()
    app.processEvents()


def test_no_unhashable_empty_list_set_membership_regression() -> None:
    source = Path("mac_audit_agent/apple_exposure_guidance.py").read_text(encoding="utf-8")
    assert "{None, \"\", []}" not in source
    assert "value not in {None, \"\", []}" not in source

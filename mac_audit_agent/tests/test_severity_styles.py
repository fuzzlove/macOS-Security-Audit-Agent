from __future__ import annotations

import re

from mac_audit_agent.ui.severity_styles import (
    SEVERITY_STYLES,
    display_severity_label,
    make_severity_badge,
    normalize_severity,
    validate_severity_styles,
)


def test_canonical_palette_has_required_solid_colors() -> None:
    assert validate_severity_styles() == []
    for label in ["none", "info", "low", "medium", "high", "critical", "unknown", "success", "healthy"]:
        style = SEVERITY_STYLES[label]
        for value in [style.background, style.foreground, style.border, style.accent]:
            assert re.match(r"^#[0-9A-Fa-f]{6}$", value)
            assert "rgba" not in value.lower()
            assert "transparent" not in value.lower()
        assert style.label


def test_core_severity_colors_are_distinct() -> None:
    backgrounds = {SEVERITY_STYLES[label].background for label in ["info", "low", "medium", "high", "critical"]}
    assert len(backgrounds) == 5


def test_normalize_text_severity_values() -> None:
    assert normalize_severity("Critical") == "critical"
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("informational") == "info"
    assert normalize_severity("review-needed") == "unknown"
    assert normalize_severity("urgent") == "critical"
    assert normalize_severity("elevated") == "high"
    assert normalize_severity("watch") == "medium"
    assert normalize_severity("clear") == "success"
    assert normalize_severity(None) == "unknown"


def test_cvss_score_mapping() -> None:
    assert normalize_severity("", 0.0, "cvss") == "none"
    assert normalize_severity("", 3.9, "cvss") == "low"
    assert normalize_severity("", 5.0, "cvss") == "medium"
    assert normalize_severity("", 7.5, "cvss") == "high"
    assert normalize_severity("", 9.8, "cvss") == "critical"


def test_security_score_and_risk_score_are_not_inverted() -> None:
    assert normalize_severity("", 95, "security_score") == "success"
    assert normalize_severity("", 35, "security_score") == "critical"
    assert normalize_severity("", 95, "risk_score") == "critical"
    assert normalize_severity("", 5, "risk_score") == "info"


def test_badge_has_visible_label_and_no_transparency() -> None:
    badge = make_severity_badge("high")
    assert 'class="severity-badge severity-high"' in badge
    assert ">HIGH</span>" in badge
    assert "rgba" not in badge.lower()
    assert "transparent" not in badge.lower()


def test_display_label_never_blank_for_unknown() -> None:
    assert display_severity_label("") == "UNKNOWN"

from __future__ import annotations

from mac_audit_agent.ui.risk_colors import RISK_COLOR_MAP, get_risk_colors, normalize_risk_label


def test_risk_color_map_has_required_solid_colors() -> None:
    for label in ["critical", "high", "medium", "low", "info", "trusted", "unknown"]:
        colors = get_risk_colors(label)
        assert colors.background.startswith("#")
        assert colors.text.startswith("#")
        assert colors.accent.startswith("#")
        assert len(colors.background) == 7
        assert len(colors.text) == 7
        assert len(colors.accent) == 7
        assert "rgba" not in colors.background.lower()


def test_risk_normalization_and_score_mapping() -> None:
    assert normalize_risk_label("Critical") == "critical"
    assert normalize_risk_label("High Risk") == "high_risk"
    assert normalize_risk_label("review-needed") == "review_needed"
    assert normalize_risk_label("", 95) == "critical"
    assert normalize_risk_label("", 75) == "high"
    assert normalize_risk_label("", 50) == "medium"
    assert normalize_risk_label("", 25) == "low"
    assert normalize_risk_label("", 5) == "info"
    assert normalize_risk_label("", None) == "unknown"

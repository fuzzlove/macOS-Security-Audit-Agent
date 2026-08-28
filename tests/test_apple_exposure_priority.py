from __future__ import annotations

from mac_audit_agent.apple_exposure_priority import apple_exposure_priority


def test_confirmed_or_likely_local_apple_exposure_takes_priority() -> None:
    result = apple_exposure_priority(
        {
            "display_cards": [
                {
                    "card_id": "macos-update",
                    "applicability": "confirmed_applicable",
                    "forecast_level": "urgent",
                    "status": "new",
                }
            ]
        }
    )

    assert result["applicable"] is True
    assert result["takes_priority"] is True
    assert result["level"] == "urgent"
    assert result["card_ids"] == ["macos-update"]


def test_review_needed_resolved_and_simulated_items_never_take_priority() -> None:
    review = apple_exposure_priority({"cards": [{"applicability": "review_needed", "forecast_level": "critical"}]})
    resolved = apple_exposure_priority(
        {"cards": [{"applicability": "confirmed_applicable", "forecast_level": "critical", "status": "resolved"}]}
    )
    simulated = apple_exposure_priority(
        {"simulated": True, "cards": [{"applicability": "confirmed_applicable", "forecast_level": "critical"}]}
    )

    assert not review["takes_priority"]
    assert not resolved["takes_priority"]
    assert not simulated["takes_priority"]


def test_local_software_update_signal_takes_priority_without_advisory_card() -> None:
    result = apple_exposure_priority({"inventory": {"software_update_available": True}})

    assert result["takes_priority"] is True
    assert result["level"] == "elevated"

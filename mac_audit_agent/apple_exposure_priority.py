from __future__ import annotations

from typing import Any, Mapping


APPLICABLE_STATES = {"confirmed_applicable", "likely_applicable"}
ACTIVE_LEVELS = {"critical", "urgent", "elevated", "watch"}


def apple_exposure_priority(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Resolve whether live Apple exposure evidence should lead current actions."""
    assessment = dict(payload or {})
    nested = assessment.get("payload_json")
    if isinstance(nested, Mapping):
        assessment = {**dict(nested), **assessment}
    if assessment.get("simulated") or str(assessment.get("source_mode", "")).startswith("demo"):
        return _result(False, "not_applicable", "Simulated Apple exposure data never receives operational priority.", [])

    cards = _cards(assessment)
    applicable: list[dict[str, Any]] = []
    for card in cards:
        if card.get("simulated") or str(card.get("source_mode", "")).startswith("demo"):
            continue
        if str(card.get("status", "new")).lower() in {"resolved", "snoozed"}:
            continue
        state = str(card.get("applicability", card.get("applicability_confidence", ""))).lower()
        level = str(card.get("forecast_level", card.get("level", ""))).lower()
        if state in APPLICABLE_STATES and (not level or level in ACTIVE_LEVELS):
            applicable.append(card)

    inventory = assessment.get("inventory")
    local_update = bool(assessment.get("apple_updates_available")) or bool(
        inventory.get("software_update_available") if isinstance(inventory, Mapping) else False
    )
    if not applicable and not local_update:
        return _result(False, "not_applicable", "No active Apple exposure item is applicable to this Mac.", [])

    levels = [str(card.get("forecast_level", "watch")).lower() for card in applicable]
    level = max(
        levels or ["elevated"],
        key=lambda item: {"watch": 1, "elevated": 2, "urgent": 3, "critical": 4}.get(item, 0),
    )
    reason = (
        f"{len(applicable)} active Apple exposure item(s) match installed software on this Mac."
        if applicable
        else "macOS Software Update reports an applicable Apple update on this Mac."
    )
    return _result(True, level, reason, applicable)


def _cards(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    source: list[Any] = []
    for key in ("display_cards", "cards", "alerts"):
        value = payload.get(key)
        if isinstance(value, list) and value:
            source = value
            break
    flattened: list[dict[str, Any]] = []
    for raw in source:
        if not isinstance(raw, Mapping):
            continue
        card = dict(raw)
        flattened.append(card)
        nested = card.get("alerts")
        if isinstance(nested, list):
            flattened.extend(dict(item) for item in nested if isinstance(item, Mapping))
    return flattened


def _result(applicable: bool, level: str, reason: str, cards: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "applicable": applicable,
        "takes_priority": applicable,
        "level": level,
        "reason": reason,
        "applicable_card_count": len(cards),
        "card_ids": [
            str(card.get("card_id", card.get("id", "")))
            for card in cards
            if card.get("card_id") or card.get("id")
        ],
        "recommended_action": (
            "Open Apple Exposure Assessment and review the applicable update guidance."
            if applicable
            else "No priority action required."
        ),
    }


__all__ = ["APPLICABLE_STATES", "ACTIVE_LEVELS", "apple_exposure_priority"]

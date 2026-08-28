from __future__ import annotations

from typing import Iterable

from .configuration import SCORE_WEIGHTS
from .models import CandidateReason, ScoreBreakdown


def _clamp(value: int) -> int:
    return max(0, min(100, int(value)))


def _damerau_levenshtein(left: str, right: str) -> int:
    left, right = left.casefold(), right.casefold()
    distances = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for index in range(len(left) + 1):
        distances[index][0] = index
    for index in range(len(right) + 1):
        distances[0][index] = index
    for row in range(1, len(left) + 1):
        for column in range(1, len(right) + 1):
            cost = 0 if left[row - 1] == right[column - 1] else 1
            distances[row][column] = min(
                distances[row - 1][column] + 1,
                distances[row][column - 1] + 1,
                distances[row - 1][column - 1] + cost,
            )
            if row > 1 and column > 1 and left[row - 1] == right[column - 2] and left[row - 2] == right[column - 1]:
                distances[row][column] = min(distances[row][column], distances[row - 2][column - 2] + 1)
    return distances[-1][-1]


def assumption_scores(canonical: str, candidate: str, human: ScoreBreakdown, impersonation: ScoreBreakdown, reasons: Iterable[CandidateReason]):
    maximum_length = max(1, len(canonical), len(candidate))
    distance = _damerau_levenshtein(canonical, candidate)
    closeness_value = _clamp(round(100 * (1 - distance / maximum_length)))
    categories = {reason.category for reason in reasons}
    deliberate_signal = 85 if categories & {"visual_confusable", "normalization_collision", "namespace_confusion"} else 70 if categories & {"combosquatting", "tld_confusion"} else 45
    similarity_signal = max(human.total, impersonation.total)
    assumption_value = _clamp(round(closeness_value * 0.42 + similarity_signal * 0.38 + deliberate_signal * 0.20))
    band = "critical" if assumption_value >= 80 else "high" if assumption_value >= 65 else "medium" if assumption_value >= 45 else "low"
    closeness = ScoreBreakdown(closeness_value, {"damerau_levenshtein_distance": distance})
    assumption = ScoreBreakdown(assumption_value, {
        "name_closeness": round(closeness_value * 0.42),
        "similarity_signals": round(similarity_signal * 0.38),
        "impersonation_pattern": round(deliberate_signal * 0.20),
    })
    return closeness, assumption, band


def score(reasons: Iterable[CandidateReason], exists: bool = False):
    contributions = {}
    human = 0
    impersonation = 0
    for reason in reasons:
        rule = reason.rule_id
        weight_key = "one_edit"
        if "OMISSION" in rule: weight_key = "omission"
        elif "REPEAT" in rule: weight_key = "repeat"
        elif "TRANSPOSE" in rule: weight_key = "transposition"
        elif "ADJACENT" in rule: weight_key = "adjacent_key"
        elif "SEPARATOR" in rule: weight_key = "separator"
        elif "PHONETIC" in rule: weight_key = "phonetic"
        elif "UNICODE" in rule: weight_key = "unicode_confusable"
        elif "NORMALIZATION" in rule: weight_key = "normalization_collision"
        elif "SERVICE_WORD" in rule: weight_key = "service_word"
        elif "TLD" in rule: weight_key = "tld_confusion"
        value = SCORE_WEIGHTS[weight_key]
        contributions[rule] = max(contributions.get(rule, 0), value)
        if reason.category in {"human_typo", "regional_keyboard", "phonetic", "separator_confusion"}:
            human += value
        if reason.category in {"visual_confusable", "normalization_collision", "combosquatting", "tld_confusion", "namespace_confusion"}:
            impersonation += value
    human_breakdown = ScoreBreakdown(_clamp(human), {key: value for key, value in contributions.items() if key.startswith(("HUMAN", "KEYBOARD", "PHONETIC"))})
    impersonation_breakdown = ScoreBreakdown(_clamp(impersonation), {key: value for key, value in contributions.items() if key not in human_breakdown.contributions})
    defensive = ScoreBreakdown(_clamp((human_breakdown.total + impersonation_breakdown.total) * 0.65), {"combined_similarity": _clamp((human_breakdown.total + impersonation_breakdown.total) * 0.65)})
    investigation = ScoreBreakdown(_clamp((human_breakdown.total + impersonation_breakdown.total) * (0.8 if exists else 0.35)), {"existing_name_weight": 80 if exists else 35})
    return human_breakdown, impersonation_breakdown, defensive, investigation

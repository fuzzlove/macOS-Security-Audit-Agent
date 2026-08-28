from __future__ import annotations

from dataclasses import dataclass

from .models import FileStatistics


@dataclass(frozen=True)
class CompatibilityClassification:
    qualifies: bool
    reason: str


def classify_compatibility(stats: FileStatistics) -> CompatibilityClassification:
    """Independent behavioral specification; no Objective-See code is copied."""
    if stats.size < 1024:
        return CompatibilityClassification(False, "below_compatibility_minimum")
    if stats.size > 50 * 1024 * 1024:
        return CompatibilityClassification(False, "above_compatibility_maximum")
    if stats.recognized_image:
        return CompatibilityClassification(False, "recognized_image_header")
    if stats.gzip_header:
        return CompatibilityClassification(False, "gzip_header")
    base64_branch = stats.base64_ratio > 0.95 and 5.9 <= stats.entropy <= 6.1
    random_branch = (
        stats.entropy >= 7.95
        and stats.monte_carlo_pi_error <= 1.5
        and (stats.monte_carlo_pi_error <= 0.5 or stats.chi_square <= 400.0)
    )
    if base64_branch:
        return CompatibilityClassification(True, "base64_encrypted_looking")
    if random_branch:
        return CompatibilityClassification(True, "high_entropy_encrypted_looking")
    return CompatibilityClassification(False, "statistics_below_threshold")

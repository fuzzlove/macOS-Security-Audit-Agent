"""Validated centralized update, retention, and staleness policy."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MalwareDefinitionPolicy:
    enabled: bool = True
    warning_stale_seconds: int = 24 * 3600
    degraded_stale_seconds: int = 72 * 3600
    critical_stale_seconds: int = 7 * 24 * 3600
    default_update_interval_seconds: int = 3600
    community_update_interval_seconds: int = 6 * 3600
    full_validation_interval_seconds: int = 24 * 3600
    jitter_seconds: int = 15 * 60
    hash_import_batch_size: int = 10_000
    retained_release_count: int = 5
    require_signed_manifests: bool = False

    def __post_init__(self) -> None:
        thresholds = (self.warning_stale_seconds, self.degraded_stale_seconds, self.critical_stale_seconds)
        if not (0 < thresholds[0] < thresholds[1] < thresholds[2]):
            raise ValueError("definition staleness thresholds must be positive and increasing")
        if not 300 <= self.default_update_interval_seconds <= 30 * 24 * 3600:
            raise ValueError("default definition update interval is outside its safe range")
        if not 0 <= self.jitter_seconds <= 3600:
            raise ValueError("definition update jitter must be between zero and one hour")
        if not 5_000 <= self.hash_import_batch_size <= 25_000:
            raise ValueError("hash import transaction batch must be between 5,000 and 25,000")
        if not 2 <= self.retained_release_count <= 50:
            raise ValueError("at least active and previous definition releases must be retained")


DEFAULT_DEFINITION_POLICY = MalwareDefinitionPolicy()


__all__ = ["DEFAULT_DEFINITION_POLICY", "MalwareDefinitionPolicy"]

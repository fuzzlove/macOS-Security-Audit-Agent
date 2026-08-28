from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class BehavioralTelemetryPolicy:
    enabled: bool = True
    profile: str = "Balanced"
    raw_retention_days: int = 3
    aggregate_retention_days: int = 180
    anomaly_retention_days: int = 730
    minimum_baseline_samples: int = 24
    established_baseline_samples: int = 168
    mature_baseline_samples: int = 720
    learning_rate: float = 0.05
    anomaly_logging_threshold: int = 40
    investigation_threshold: int = 60
    alert_threshold: int = 80
    baseline_update_interval_seconds: int = 86_400
    bucket_seconds: int = 300
    queue_capacity: int = 4096
    batch_size: int = 256
    correlation_window_seconds: int = 900
    pre_event_window_seconds: int = 300
    post_event_window_seconds: int = 300
    wake_grace_seconds: int = 180
    startup_grace_seconds: int = 300
    maximum_entities_per_bucket: int = 256
    maximum_evidence_refs_per_bucket: int = 512

    def __post_init__(self) -> None:
        if not 1 <= self.raw_retention_days <= self.aggregate_retention_days <= 3650:
            raise ValueError("retention must be ordered and bounded")
        if self.anomaly_retention_days < self.aggregate_retention_days:
            raise ValueError("anomaly retention cannot be shorter than aggregate retention")
        if not 0 < self.learning_rate <= 0.25:
            raise ValueError("learning rate must be in (0, 0.25]")
        thresholds = (self.anomaly_logging_threshold, self.investigation_threshold, self.alert_threshold)
        if not 0 <= thresholds[0] < thresholds[1] < thresholds[2] <= 100:
            raise ValueError("behavioral thresholds must be ordered from 0 to 100")
        samples = (self.minimum_baseline_samples, self.established_baseline_samples, self.mature_baseline_samples)
        if not 1 <= samples[0] <= samples[1] <= samples[2]:
            raise ValueError("baseline sample thresholds must be ordered")
        if not 60 <= self.bucket_seconds <= 86_400:
            raise ValueError("bucket size must be between one minute and one day")
        if not 64 <= self.queue_capacity <= 1_000_000 or not 1 <= self.batch_size <= self.queue_capacity:
            raise ValueError("queue and batch bounds are invalid")


PROFILE_POLICIES = {
    "Balanced": BehavioralTelemetryPolicy(),
    "Office": replace(BehavioralTelemetryPolicy(), profile="Office", investigation_threshold=60, alert_threshold=80),
    "High Security": replace(BehavioralTelemetryPolicy(), profile="High Security", investigation_threshold=55, alert_threshold=75),
    "Developer": replace(BehavioralTelemetryPolicy(), profile="Developer", investigation_threshold=65, alert_threshold=85),
    "Research": replace(BehavioralTelemetryPolicy(), profile="Research", investigation_threshold=70, alert_threshold=90),
    "Enterprise": replace(BehavioralTelemetryPolicy(), profile="Enterprise", raw_retention_days=7, aggregate_retention_days=365),
    "Server": replace(BehavioralTelemetryPolicy(), profile="Server", investigation_threshold=60, alert_threshold=80),
}


def policy_for_profile(name: str) -> BehavioralTelemetryPolicy:
    return PROFILE_POLICIES.get(str(name or "").strip(), PROFILE_POLICIES["Balanced"])


__all__ = ["BehavioralTelemetryPolicy", "PROFILE_POLICIES", "policy_for_profile"]

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AlertingConfig:
    schema_version: int = 1
    dedup_window_seconds: int = 60
    summary_interval_seconds: int = 300
    resolve_after_seconds: int = 900
    summary_thresholds: tuple[int, ...] = (10, 100, 1000)
    ingestion_capacity: int = 10_000
    notification_capacity: int = 2_000
    protected_capacity: int = 500
    maximum_active_fingerprints: int = 50_000
    state_ttl_seconds: int = 86_400
    maximum_size_mb: int = 2_048
    emergency_reserved_size_mb: int = 256
    individual_duplicate_retention_limit: int = 1_000
    maximum_event_size_bytes: int = 262_144
    maximum_string_length: int = 16_384
    desktop_notifications_per_minute: int = 6
    flood_events_per_window: int = 1_000
    source_rate_per_second: int = 2_000
    maximum_source_windows: int = 4_096
    emergency_buffer_capacity: int = 512
    fallback_audit_maximum_bytes: int = 1_048_576
    maximum_suppression_duration_seconds: int = 86_400
    maximum_nesting_depth: int = 8
    maximum_collection_items: int = 128
    event_integrity_chain_enabled: bool = True
    source_authentication_enabled: bool = True

    def validate(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported alerting configuration schema")
        positive = (self.dedup_window_seconds, self.summary_interval_seconds, self.resolve_after_seconds, self.ingestion_capacity, self.notification_capacity, self.protected_capacity, self.maximum_active_fingerprints, self.maximum_event_size_bytes, self.maximum_source_windows, self.emergency_buffer_capacity, self.fallback_audit_maximum_bytes, self.maximum_suppression_duration_seconds, self.maximum_nesting_depth, self.maximum_collection_items)
        if any(value <= 0 for value in positive):
            raise ValueError("alerting limits must be positive")
        if self.protected_capacity >= self.ingestion_capacity:
            raise ValueError("protected capacity must be smaller than ingestion capacity")
        if tuple(sorted(set(self.summary_thresholds))) != self.summary_thresholds or any(value <= 1 for value in self.summary_thresholds):
            raise ValueError("summary thresholds must be unique, increasing, and greater than one")
        if self.emergency_reserved_size_mb >= self.maximum_size_mb:
            raise ValueError("emergency reserve must be smaller than the storage quota")


def load_alerting_config(path: Path | None = None) -> AlertingConfig:
    if path is None:
        path = Path(__file__).resolve().parents[1] / "config" / "alerting.json"
    config = AlertingConfig()
    if path and path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        allowed = set(AlertingConfig.__dataclass_fields__)
        values = {key: value for key, value in payload.get("alerting", payload).items() if key in allowed}
        if "summary_thresholds" in values:
            values["summary_thresholds"] = tuple(int(item) for item in values["summary_thresholds"])
        config = AlertingConfig(**values)
    config.validate()
    return config

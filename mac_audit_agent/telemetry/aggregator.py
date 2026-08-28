from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from mac_audit_agent.telemetry.models import AnalyticsAvailability, NormalizedTelemetryEvent, TelemetryBucket
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.storage import TelemetryRepository


class TelemetryAggregator:
    def __init__(self, repository: TelemetryRepository, policy: BehavioralTelemetryPolicy) -> None:
        self.repository = repository
        self.policy = policy

    def aggregate(self, events: Iterable[NormalizedTelemetryEvent]) -> list[TelemetryBucket]:
        groups: dict[tuple[str, str, str, str], list[NormalizedTelemetryEvent]] = defaultdict(list)
        for event in events:
            start, _end = bucket_bounds(event.timestamp, self.policy.bucket_seconds)
            context = self._context_cohort(event)
            groups[(start, event.host_ref, event.user_ref, context)].append(event)
            groups[(start, event.host_ref, "", context)].append(event)

        updated: list[TelemetryBucket] = []
        for (start, host_ref, user_ref, context), items in groups.items():
            end = bucket_bounds(items[0].timestamp, self.policy.bucket_seconds)[1]
            cohort = time_cohort(start)
            bucket = self.repository.get_bucket(start, host_ref, user_ref, context) or TelemetryBucket(
                bucket_start=start, bucket_end=end, host_ref=host_ref, user_ref=user_ref,
                time_cohort=cohort, context_cohort=context,
            )
            for event in items:
                self.repository.record_event_link(event, raw_retention_days=self.policy.raw_retention_days)
                self.repository.update_entity_profiles(event)
                self._merge(bucket, event)
            self.repository.upsert_bucket(bucket)
            updated.append(bucket)
        self.repository.commit()
        return updated

    def _merge(self, bucket: TelemetryBucket, event: NormalizedTelemetryEvent) -> None:
        for name, value in event.features.items():
            previous = bucket.feature_values.get(name)
            bucket.feature_values[name] = float(previous or 0.0) + float(value)
        risk_features = {
            "risk_first_seen_count": bool(event.security_context.get("first_seen")),
            "risk_unsigned_count": bool(event.security_context.get("unsigned")),
            "risk_downloads_path_count": bool(event.security_context.get("downloads_path")),
            "risk_temporary_path_count": bool(event.security_context.get("temporary_path")),
            "risk_privileged_count": bool(event.security_context.get("privileged")),
            "risk_known_malicious_count": bool(event.security_context.get("known_malicious")),
        }
        for name, present in risk_features.items():
            if present:
                bucket.feature_values[name] = float(bucket.feature_values.get(name) or 0.0) + 1.0
        dimension = event.dimension.value
        bucket.dimension_values[dimension] = float(bucket.dimension_values.get(dimension) or 0.0) + sum(event.features.values())
        bucket.coverage[dimension] = event.coverage.value
        overrides = event.security_context.get("coverage_overrides", {})
        if isinstance(overrides, dict):
            for affected_dimension, state in list(overrides.items())[:16]:
                normalized_state = str(state).upper()
                if normalized_state in {item.value for item in AnalyticsAvailability}:
                    bucket.coverage[str(affected_dimension)[:128]] = normalized_state
                    if normalized_state in {AnalyticsAvailability.UNKNOWN.value, AnalyticsAvailability.UNAVAILABLE.value}:
                        bucket.dimension_values[str(affected_dimension)[:128]] = None
        for entity_type, entity_ref in event.entity_keys.items():
            values = set(bucket.entity_sets.get(entity_type, []))
            if len(values) < self.policy.maximum_entities_per_bucket:
                values.add(entity_ref)
            bucket.entity_sets[entity_type] = sorted(values)
        refs = list(dict.fromkeys([*bucket.evidence_refs, *event.evidence_refs]))
        bucket.evidence_refs = refs[-self.policy.maximum_evidence_refs_per_bucket :]
        bucket.training_eligible = bucket.training_eligible and event.baseline_training_eligible
        bucket.event_count += 1

    @staticmethod
    def _context_cohort(event: NormalizedTelemetryEvent) -> str:
        name = event.event_name
        explicit = str(event.security_context.get("context_cohort") or "").upper()
        if explicit in {"STARTUP", "WAKE_GRACE", "MAINTENANCE", "RESEARCH", "STEADY_STATE"}:
            return explicit
        if event.security_context.get("research_mode"):
            return "RESEARCH"
        if event.security_context.get("maintenance_context"):
            return "MAINTENANCE"
        if "wake" in name:
            return "WAKE_GRACE"
        if "startup" in name or "boot" in name:
            return "STARTUP"
        return "STEADY_STATE"


def bucket_bounds(timestamp: str, bucket_seconds: int) -> tuple[str, str]:
    parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    epoch = int(parsed.timestamp())
    start_epoch = epoch - epoch % bucket_seconds
    start = datetime.fromtimestamp(start_epoch, timezone.utc)
    end = start + timedelta(seconds=bucket_seconds)
    return start.isoformat(), end.isoformat()


def time_cohort(timestamp: str) -> str:
    parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    local = parsed.astimezone()
    return f"{'WEEKEND' if local.weekday() >= 5 else 'WEEKDAY'}:{local.hour:02d}"


__all__ = ["TelemetryAggregator", "bucket_bounds", "time_cohort"]

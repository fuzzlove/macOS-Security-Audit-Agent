from __future__ import annotations

import hashlib
import statistics
from collections import defaultdict
from typing import Iterable

from mac_audit_agent.telemetry.models import (
    BEHAVIOR_MODEL_VERSION, FEATURE_SCHEMA_VERSION, BaselineState, FeatureBaseline, TelemetryBucket, utc_now_iso,
)
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.storage import TelemetryRepository


class BehaviorBaselineEngine:
    def __init__(self, repository: TelemetryRepository, policy: BehavioralTelemetryPolicy) -> None:
        self.repository = repository
        self.policy = policy

    def rebuild(self, *, reason: str = "scheduled robust baseline rebuild", actor: str = "behavioral_telemetry") -> dict:
        all_buckets = self.repository.list_buckets(limit=100_000)
        eligible = [bucket for bucket in all_buckets if bucket.training_eligible and bucket.context_cohort not in {"RESEARCH", "MAINTENANCE"}]
        version = self.repository.create_baseline_version(
            training_start=min((item.bucket_start for item in eligible), default=""),
            training_end=max((item.bucket_end for item in eligible), default=""),
            bucket_count=len(eligible), excluded_count=len(all_buckets) - len(eligible),
            feature_schema_version=FEATURE_SCHEMA_VERSION, behavior_model_version=BEHAVIOR_MODEL_VERSION, reason=reason,
        )
        baselines = self._build(eligible, version)
        self.repository.save_baselines(baselines)
        self.repository.set_state("last_baseline_update", utc_now_iso())
        self.repository.set_state("baseline_version", version)
        self.repository.audit(
            actor=actor, action="baseline_rebuild", object_type="telemetry_baseline", object_id=str(version),
            current={"version": version, "features": len(baselines), "eligible_buckets": len(eligible), "excluded_buckets": len(all_buckets) - len(eligible)},
            reason=reason,
        )
        self.repository.commit()
        return {"version": version, "baseline_count": len(baselines), "eligible_buckets": len(eligible), "excluded_buckets": len(all_buckets) - len(eligible)}

    def _build(self, buckets: Iterable[TelemetryBucket], version: int) -> list[FeatureBaseline]:
        grouped: dict[tuple[str, str, str, str, str], list[float]] = defaultdict(list)
        for bucket in buckets:
            for feature, value in bucket.feature_values.items():
                if value is None:
                    continue
                for cohort in (bucket.time_cohort, "ALL"):
                    grouped[(bucket.host_ref, bucket.user_ref, feature, cohort, bucket.context_cohort)].append(float(value))
                    if bucket.context_cohort != "ALL":
                        grouped[(bucket.host_ref, bucket.user_ref, feature, cohort, "ALL")].append(float(value))
        now = utc_now_iso()
        output: list[FeatureBaseline] = []
        for (host, user, feature, cohort, context), values in grouped.items():
            values.sort()
            count = len(values)
            median = statistics.median(values)
            deviations = [abs(value - median) for value in values]
            mad = statistics.median(deviations) if deviations else 0.0
            state, confidence = self._state(count)
            identity = f"{host}|{user}|{feature}|{cohort}|{context}|{version}"
            output.append(FeatureBaseline(
                baseline_id="baseline-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
                host_ref=host,user_ref=user,feature_name=feature,time_cohort=cohort,context_cohort=context,
                median_value=median,mad_value=mad,p05=_percentile(values,0.05),p25=_percentile(values,0.25),
                p50=_percentile(values,0.50),p75=_percentile(values,0.75),p95=_percentile(values,0.95),
                sample_count=count,confidence=confidence,state=state,version=version,updated_at=now,
            ))
        return output

    def _state(self, samples: int) -> tuple[BaselineState, float]:
        if samples < self.policy.minimum_baseline_samples:
            return BaselineState.LEARNING, min(0.24, samples / max(1, self.policy.minimum_baseline_samples) * 0.24)
        if samples < self.policy.established_baseline_samples:
            span = self.policy.established_baseline_samples - self.policy.minimum_baseline_samples
            return BaselineState.LOW_CONFIDENCE, 0.25 + 0.34 * (samples - self.policy.minimum_baseline_samples) / max(1, span)
        if samples < self.policy.mature_baseline_samples:
            span = self.policy.mature_baseline_samples - self.policy.established_baseline_samples
            return BaselineState.ESTABLISHED, 0.60 + 0.29 * (samples - self.policy.established_baseline_samples) / max(1, span)
        return BaselineState.MATURE, min(1.0, 0.90 + 0.10 * samples / max(samples, self.policy.mature_baseline_samples * 2))


def _percentile(sorted_values: list[float], quantile: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction


__all__ = ["BehaviorBaselineEngine"]

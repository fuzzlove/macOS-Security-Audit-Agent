from __future__ import annotations

import queue
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from mac_audit_agent.telemetry.aggregator import TelemetryAggregator
from mac_audit_agent.telemetry.anomaly import AnomalyDetectionEngine
from mac_audit_agent.telemetry.baseline import BehaviorBaselineEngine
from mac_audit_agent.telemetry.correlation import BehavioralCorrelationEngine
from mac_audit_agent.telemetry.models import NormalizedTelemetryEvent, utc_now_iso
from mac_audit_agent.telemetry.normalizer import TelemetryNormalizer
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy, policy_for_profile
from mac_audit_agent.telemetry.storage import TelemetryRepository, open_telemetry_connection
from mac_audit_agent.telemetry.workstation_profiles import apply_workstation_profile, workstation_profile


class TelemetryManager:
    """Bounded, non-privileged behavioral processing isolated from sensor ingestion."""

    def __init__(self, database: Any, policy: BehavioralTelemetryPolicy | None = None, *, autostart: bool = True) -> None:
        self.db = database
        self.policy = policy or self._load_policy()
        self._owned_connection = open_telemetry_connection(database.path) if hasattr(database, "path") else None
        self.repository = TelemetryRepository(self._owned_connection or database)
        self.normalizer = TelemetryNormalizer(host_salt=str(database.path))
        self.aggregator = TelemetryAggregator(self.repository, self.policy)
        self.baselines = BehaviorBaselineEngine(self.repository, self.policy)
        self.anomalies = AnomalyDetectionEngine(self.repository, self.policy)
        self.correlation = BehavioralCorrelationEngine(database, self.repository, self.policy)
        self._queue: queue.Queue[NormalizedTelemetryEvent] = queue.Queue(maxsize=self.policy.queue_capacity)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics_lock = threading.Lock()
        self._metrics = {
            "events_received": 0,"events_aggregated": 0,"analysis_count": 0,"anomaly_count": 0,
            "dropped_telemetry": 0,"error_count": 0,"queue_peak": 0,"aggregation_latency_ms": 0.0,"analysis_latency_ms": 0.0,
            "last_raw_event": "","last_bucket_completed": "","last_baseline_update": self.repository.state("last_baseline_update", ""),
            "last_analysis": "","state": "LEARNING",
        }
        if autostart and self.policy.enabled:
            self.start()

    def _load_policy(self) -> BehavioralTelemetryPolicy:
        try:
            profile = self.db.get_background_monitor_state("behavioral_telemetry_profile", "Balanced")
        except Exception:
            profile = "Balanced"
        return policy_for_profile(str(profile))

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="msaa-behavioral-telemetry", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))
        self._thread = None

    def close(self, timeout: float = 3.0) -> None:
        self.stop(timeout)
        if self._owned_connection is not None:
            self._owned_connection.close()
            self._owned_connection = None

    def submit_background_event(self, event: Any) -> bool:
        if not self.policy.enabled:
            return False
        try:
            normalized = self.normalizer.normalize(event)
        except (TypeError, ValueError):
            self._increment("error_count")
            return False
        if normalized is None:
            return False
        self._increment("events_received")
        self._metrics["last_raw_event"] = normalized.timestamp
        try:
            self._queue.put_nowait(normalized)
            with self._metrics_lock:
                self._metrics["queue_peak"] = max(self._metrics["queue_peak"], self._queue.qsize())
            return True
        except queue.Full:
            self._increment("dropped_telemetry")
            self._metrics["state"] = "DEGRADED"
            self.repository.set_state("queue_overflow", {"at": utc_now_iso(), "capacity": self.policy.queue_capacity})
            self.repository.commit()
            return False

    def process_event_sync(self, event: Any, *, force_analysis: bool = True) -> list[dict[str, Any]]:
        normalized = self.normalizer.normalize(event)
        if normalized is None:
            return []
        self._increment("events_received")
        self._metrics["last_raw_event"] = normalized.timestamp
        return [item.to_dict() for item in self._process_batch([normalized], force_analysis=force_analysis)]

    def process_events_sync(self, events: list[Any], *, force_analysis: bool = True) -> list[dict[str, Any]]:
        """Deterministic batch path for imports, replay, and synthetic tests."""
        normalized: list[NormalizedTelemetryEvent] = []
        for event in events:
            try:
                item = self.normalizer.normalize(event)
            except (TypeError, ValueError):
                self._increment("error_count")
                continue
            if item is None:
                continue
            normalized.append(item)
            self._increment("events_received")
            self._metrics["last_raw_event"] = item.timestamp
        if not normalized:
            return []
        return [item.to_dict() for item in self._process_batch(normalized, force_analysis=force_analysis)]

    def flush(self) -> None:
        batch: list[NormalizedTelemetryEvent] = []
        while len(batch) < self.policy.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._process_batch(batch)
            for _ in batch:
                self._queue.task_done()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < self.policy.batch_size:
                try: batch.append(self._queue.get_nowait())
                except queue.Empty: break
            try:
                self._process_batch(batch)
            except Exception:
                self._increment("error_count")
                self._metrics["state"] = "DEGRADED"
            finally:
                for _ in batch: self._queue.task_done()

    def _process_batch(self, batch: list[NormalizedTelemetryEvent], *, force_analysis: bool = False):
        started = time.monotonic()
        batch = [apply_workstation_profile(event, self.policy.profile) for event in batch]
        batch = self._enrich_first_seen(batch)
        buckets = self.aggregator.aggregate(batch)
        aggregation_ms = (time.monotonic() - started) * 1000
        self._increment("events_aggregated", len(batch))
        self._metrics["aggregation_latency_ms"] = round(aggregation_ms, 3)
        had_baseline = self.repository.latest_baseline_version() > 0
        if not had_baseline:
            self._maybe_rebuild_baseline()
        analysis_started = time.monotonic()
        created = []
        now = datetime.now(timezone.utc)
        for bucket in buckets:
            if not bucket.user_ref or not self.repository.bucket_needs_analysis(bucket):
                continue
            bucket_end = _parse(bucket.bucket_end)
            if not force_analysis and bucket_end > now:
                continue
            anomalies = self.anomalies.analyze_bucket(bucket)
            for anomaly in anomalies:
                self.repository.save_anomaly(anomaly)
            self.repository.commit()
            serious = [item for item in anomalies if item.anomaly_score >= self.policy.investigation_threshold]
            if serious:
                # The current deviation cannot join future training until an
                # operator or sustained legitimate history provides context.
                self.repository.set_bucket_training_eligible(bucket, False)
                for companion in buckets:
                    if (
                        companion.user_ref == ""
                        and companion.host_ref == bucket.host_ref
                        and companion.bucket_start == bucket.bucket_start
                        and companion.context_cohort == bucket.context_cohort
                    ):
                        self.repository.set_bucket_training_eligible(companion, False)
                self.repository.commit()
                self.correlation.correlate(serious)
            self.repository.mark_bucket_analyzed(bucket, [item.anomaly_id for item in anomalies])
            created.extend(anomalies)
            self._increment("analysis_count")
            self._increment("anomaly_count", len(anomalies))
            self._metrics["last_bucket_completed"] = bucket.bucket_end
        if had_baseline:
            self._maybe_rebuild_baseline()
        self._metrics["analysis_latency_ms"] = round((time.monotonic() - analysis_started) * 1000, 3)
        self._metrics["last_analysis"] = utc_now_iso()
        self._metrics["state"] = "DEGRADED" if self._metrics["dropped_telemetry"] else "OPERATIONAL"
        self.repository.set_state("health_metrics", self.health())
        self.repository.commit()
        return created

    def _enrich_first_seen(self, batch: list[NormalizedTelemetryEvent]) -> list[NormalizedTelemetryEvent]:
        seen_in_batch: set[tuple[str, str]] = set()
        output: list[NormalizedTelemetryEvent] = []
        for event in batch:
            new_entities = [
                (entity_type, entity_ref)
                for entity_type, entity_ref in event.entity_keys.items()
                if (entity_type, entity_ref) not in seen_in_batch and not self.repository.entity_seen(entity_type, entity_ref)
            ]
            seen_in_batch.update(event.entity_keys.items())
            if not new_entities:
                output.append(event)
                continue
            context = dict(event.security_context)
            features = dict(event.features)
            if any(entity_type in {"process", "path", "signing_identifier", "team_identifier"} for entity_type, _ in new_entities):
                context["first_seen"] = True
                if event.dimension.value == "PROCESS_ACTIVITY":
                    features["first_seen_process_count"] = max(1.0, float(features.get("first_seen_process_count") or 0.0))
            output.append(replace(event, features=features, security_context=context))
        return output

    def _maybe_rebuild_baseline(self) -> None:
        last = str(self.repository.state("last_baseline_update", "") or "")
        eligible = self.repository.list_buckets(training_eligible=True, limit=self.policy.minimum_baseline_samples + 1)
        due = not last or (datetime.now(timezone.utc) - _parse(last)).total_seconds() >= self.policy.baseline_update_interval_seconds
        if due and len(eligible) >= self.policy.minimum_baseline_samples:
            result = self.baselines.rebuild()
            self._metrics["last_baseline_update"] = utc_now_iso()
            self._metrics["state"] = "OPERATIONAL" if result["baseline_count"] else "LEARNING"

    def rebuild_baseline(self, *, actor: str, reason: str) -> dict[str, Any]:
        return self.baselines.rebuild(reason=reason, actor=actor)

    def set_workstation_profile(self, name: str, *, actor: str = "local_operator") -> str:
        selected = workstation_profile(name).name
        previous = self.policy.profile
        if selected == previous:
            return selected
        policy = policy_for_profile(selected)
        self.policy = policy
        self.aggregator.policy = policy
        self.baselines.policy = policy
        self.anomalies.policy = policy
        self.correlation.policy = policy
        self.db.set_background_monitor_state("behavioral_telemetry_profile", selected)
        self.repository.set_state("active_workstation_profile", selected)
        self.repository.audit(
            actor=actor,
            action="workstation_profile_change",
            object_type="behavioral_telemetry_policy",
            object_id="active_workstation_profile",
            previous={"profile": previous},
            current={"profile": selected},
            reason="Operator changed the declared workstation role.",
        )
        self.repository.commit()
        return selected

    def health(self) -> dict[str, Any]:
        with self._metrics_lock:
            metrics = dict(self._metrics)
        metrics.update({
            "queue_depth": self._queue.qsize(),"queue_capacity": self.policy.queue_capacity,
            "queue_latency": None,"analysis_availability": "DEGRADED" if metrics["dropped_telemetry"] else "AVAILABLE",
            "policy_profile": self.policy.profile,"worker_alive": bool(self._thread and self._thread.is_alive()),
            "workstation_profile_description": workstation_profile(self.policy.profile).description,
        })
        return metrics

    def doctor(self) -> dict[str, Any]:
        baseline_version = self.repository.latest_baseline_version()
        buckets = self.repository.list_buckets(limit=1)
        return {
            "status": "DEGRADED" if self.health()["analysis_availability"] == "DEGRADED" else "PASS",
            "checks": {
                "event_ingestion": bool(self._metrics["last_raw_event"]),"aggregation": bool(buckets),"database": True,
                "baseline_status": "AVAILABLE" if baseline_version else "LEARNING","queue_health": self._queue.qsize() < self.policy.queue_capacity,
                "last_analysis": self._metrics["last_analysis"],"sensor_coverage": "PARTIAL" if not buckets else "OBSERVED",
            },
            "metrics": self.health(),
        }

    def summary(self, *, hours: int = 24) -> dict[str, Any]:
        since = (datetime.now(timezone.utc) - timedelta(hours=max(1, min(hours, 24 * 365)))).isoformat()
        buckets = self.repository.list_buckets(since=since, limit=20_000)
        anomalies = self.repository.list_anomalies(since=since, limit=1000)
        dimensions: dict[str, float | None] = {}
        coverage: dict[str, str] = {}
        for bucket in buckets:
            if bucket.user_ref:
                continue
            for name, value in bucket.dimension_values.items():
                dimensions[name] = float(dimensions.get(name) or 0.0) + float(value or 0.0)
            coverage.update(bucket.coverage)
        return {
            "window_hours": hours,"state": "HIGH_DEVIATION" if any(item["anomaly_score"] >= 80 for item in anomalies) else "UNUSUAL" if anomalies else "NORMAL" if buckets else "LEARNING",
            "baseline_version": self.repository.latest_baseline_version(),"baseline_status": "ESTABLISHED" if self.repository.latest_baseline_version() else "LEARNING",
            "dimensions": dimensions,"coverage": coverage,"anomalies": anomalies,
            "anomalies_today": len(anomalies),"high_risk_anomalies": sum(item["security_severity"] in {"high", "critical"} for item in anomalies),
            "health": self.health(),
        }

    def _increment(self, name: str, amount: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[name] = int(self._metrics.get(name, 0)) + amount


def manager_for(database: Any, *, autostart: bool = True) -> TelemetryManager:
    manager = getattr(database, "_behavioral_telemetry_manager", None)
    if manager is None:
        manager = TelemetryManager(database, autostart=autostart)
        setattr(database, "_behavioral_telemetry_manager", manager)
    elif autostart:
        manager.start()
    return manager


def _parse(value: str) -> datetime:
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


__all__ = ["TelemetryManager", "manager_for"]

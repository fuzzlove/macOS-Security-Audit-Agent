"""Sensor Reliability Coordinator: isolated checks, propagation, recovery, evidence."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .evaluator import HysteresisTracker, SensorHealthEvaluator, build_platform_report
from .models import (
    DependencyState, PlatformHealthReport, ReasonCode, SelfTestResult, SensorDependency,
    SensorHealthProvider, SensorHealthSnapshot, SensorState, utc_now,
)
from .persistence import SensorHealthStore
from .policies import SensorHealthPolicy, policy_for
from .recovery import RecoveryEngine
from .registry import SensorRegistry
from .surgical_repair import build_surgical_repair_plan, render_surgical_repair_transcript


class SensorReliabilityCoordinator:
    """Proves functional coverage; never substitutes process liveness for health."""

    def __init__(
        self,
        store: SensorHealthStore,
        registry: SensorRegistry,
        *,
        evaluator: SensorHealthEvaluator | None = None,
        recovery: RecoveryEngine | None = None,
        policies: dict[str, SensorHealthPolicy] | None = None,
        fault_injector=None,
        max_workers: int = 4,
    ) -> None:
        self.store = store
        self.registry = registry
        self.evaluator = evaluator or SensorHealthEvaluator()
        self.recovery = recovery or RecoveryEngine()
        self.policies = policies or {}
        self.max_workers = max(1, min(16, int(max_workers)))
        self.fault_injector = fault_injector
        self.hysteresis = HysteresisTracker()
        self.last_report: PlatformHealthReport | None = None
        self.manager_state: dict[str, object] = {
            "last_health_cycle": "", "last_successful_health_cycle": "",
            "sensors_checked": 0, "health_checks_failed": 0, "health_cycle_duration_ms": 0.0,
        }

    def register(self, providers: Iterable[SensorHealthProvider]) -> None:
        for provider in providers:
            self.registry.register(provider)

    def close(self) -> None:
        """Release persistent health-store resources owned by this coordinator."""
        self.store.close()

    def run_cycle(self, *, run_self_tests: bool = False, auto_recover: bool = True) -> PlatformHealthReport:
        cycle_started_monotonic = time.monotonic()
        cycle_started_at = utc_now()
        self.manager_state["cycle_started_at"] = cycle_started_at
        providers = self.registry.providers()
        raw: dict[str, SensorHealthSnapshot] = {}
        failures = 0
        executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="msaa-sensor-health")
        future_map = {executor.submit(provider.health_snapshot): provider for provider in providers}
        timeout = max((self._policy(provider.sensor_id()).provider_timeout_seconds for provider in providers), default=5.0)
        completed, pending = wait(tuple(future_map), timeout=timeout)
        for future in completed:
            provider = future_map[future]
            try:
                snapshot = future.result()
                if snapshot.sensor_id != provider.sensor_id():
                    raise ValueError("provider sensor_id does not match snapshot")
                raw[snapshot.sensor_id] = self.fault_injector.apply(snapshot) if self.fault_injector is not None else snapshot
            except Exception as exc:
                failures += 1
                raw[provider.sensor_id()] = self._provider_failure(provider.sensor_id(), ReasonCode.HEALTH_PROVIDER_INVALID, f"Health provider failed in isolation: {type(exc).__name__}: {exc}")
        for future in pending:
            provider = future_map[future]
            failures += 1
            future.cancel()
            raw[provider.sensor_id()] = self._provider_failure(provider.sensor_id(), ReasonCode.HEALTH_PROVIDER_TIMEOUT, "Health provider exceeded its bounded timeout; other sensors were still checked.")
        executor.shutdown(wait=False, cancel_futures=True)

        for descriptor in self.registry.missing_expected():
            raw[descriptor.sensor_id] = self._provider_failure(descriptor.sensor_id, ReasonCode.HEALTH_PROVIDER_INVALID, "Expected sensor did not register during startup.")

        self._propagate_sensor_dependencies(raw)
        maintenance = self._active_maintenance()
        previous_states: dict[str, SensorState] = {}
        evaluated: list[tuple[object, SensorHealthSnapshot]] = []
        for descriptor in self.registry.descriptors():
            if descriptor.sensor_id not in raw:
                continue
            prior_payload = self.store.current_snapshot(descriptor.sensor_id)
            prior = self._prior_snapshot(prior_payload)
            previous_states[descriptor.sensor_id] = prior.state if prior else SensorState.UNKNOWN
            provider = self.registry.provider(descriptor.sensor_id)
            snapshot = raw[descriptor.sensor_id]
            if run_self_tests and provider is not None:
                snapshot = replace(snapshot, last_self_test=self._bounded_self_test(provider, self._policy(descriptor.sensor_id)))
            result = self.evaluator.evaluate(snapshot, self._policy(descriptor.sensor_id))
            if maintenance:
                result = replace(result, state=SensorState.MAINTENANCE, reason_code=ReasonCode.MAINTENANCE_ACTIVE,
                                 reason=f"Controlled maintenance: {maintenance['reason']}", operator_action_required=False)
            result = self.hysteresis.apply(result, prior, self._policy(descriptor.sensor_id))
            if auto_recover and provider is not None and result.state in {SensorState.FAILED, SensorState.IMPAIRED, SensorState.STALE, SensorState.DEPENDENCY_FAILED, SensorState.BACKPRESSURED}:
                started = utc_now()
                recovery_result = self.recovery.recover(provider, result, self._policy(descriptor.sensor_id))
                self.store.record_recovery(descriptor.sensor_id, result.reason_code.value, recovery_result, started_at=started)
                if recovery_result.succeeded:
                    verification = self._bounded_self_test(provider, self._policy(descriptor.sensor_id))
                    result = replace(
                        result,
                        state=SensorState.RECOVERING if verification.passed else SensorState.IMPAIRED,
                        reason_code=ReasonCode.RECOVERY_IN_PROGRESS if verification.passed else ReasonCode.RECOVERY_VALIDATION_FAILED,
                        reason="Targeted recovery completed; stabilization evidence is still being collected." if verification.passed else f"Recovery did not restore functional evidence: {verification.reason}",
                        last_self_test=verification,
                    )
            result = replace(result, metadata={**result.metadata, "criticality": descriptor.criticality.value, "failure_domain": descriptor.failure_domain})
            evaluated.append((descriptor, result))

        duration_ms = (time.monotonic() - cycle_started_monotonic) * 1000
        self.manager_state.update({
            "last_health_cycle": cycle_started_at.isoformat().replace("+00:00", "Z"),
            "last_successful_health_cycle": utc_now().isoformat().replace("+00:00", "Z") if evaluated else str(self.manager_state.get("last_successful_health_cycle", "")),
            "sensors_checked": len(evaluated), "health_checks_failed": failures,
            "health_cycle_duration_ms": round(duration_ms, 3),
        })
        report = build_platform_report(evaluated, manager_health=dict(self.manager_state))
        self.store.persist_report(report, previous_states)
        self.store.set_manager_state("coordinator_health", dict(self.manager_state))
        self.last_report = report
        return report

    def enter_maintenance(self, reason: str, initiated_by: str, *, timeout_seconds: int = 1800) -> dict:
        reason = str(reason).strip()[:256]
        initiated_by = str(initiated_by).strip()[:128]
        if not reason or not initiated_by or not 30 <= timeout_seconds <= 86_400:
            raise ValueError("maintenance requires a reason, initiator, and timeout between 30 and 86400 seconds")
        payload = {"reason": reason, "initiated_by": initiated_by, "started_at": time.time(), "expires_at": time.time() + timeout_seconds}
        self.store.set_manager_state("maintenance", payload)
        return payload

    def exit_maintenance(self) -> None:
        self.store.set_manager_state("maintenance", {})

    def _active_maintenance(self) -> dict:
        payload = self.store.get_manager_state("maintenance", {})
        if not isinstance(payload, dict) or not payload.get("reason"):
            return {}
        if float(payload.get("expires_at", 0)) <= time.time():
            self.store.set_manager_state("maintenance", {})
            return {}
        return payload

    def recover_sensor(self, sensor_id: str) -> dict:
        provider = self.registry.provider(sensor_id)
        if provider is None:
            raise ValueError(f"unknown or unregistered sensor: {sensor_id}")
        snapshot = self.evaluator.evaluate(provider.health_snapshot(), self._policy(sensor_id))
        pre_repair = snapshot.to_dict()
        repair_plan = build_surgical_repair_plan(pre_repair)
        repair_trace: list[dict[str, str]] = []
        errors: list[str] = []

        def trace(stage: str, status: str, detail: str) -> None:
            repair_trace.append({
                "timestamp": utc_now().isoformat().replace("+00:00", "Z"),
                "stage": str(stage),
                "status": str(status),
                "detail": str(detail)[:4000],
            })

        trace(
            "diagnosis",
            "complete",
            f"state={snapshot.state.value}; reason_code={snapshot.reason_code.value}; lost_capabilities={','.join(snapshot.lost_capabilities) or 'none'}",
        )
        healthy_states = {SensorState.HEALTHY, SensorState.HEALTHY_IDLE}
        if snapshot.state in healthy_states and not snapshot.lost_capabilities:
            trace("repair decision", "skipped", "Functional evidence is healthy; no mutation was justified.")
            payload = {
                "sensor_id": sensor_id,
                "reason_code": snapshot.reason_code.value,
                "recovery": {
                    "attempted": False,
                    "succeeded": True,
                    "action": "OBSERVE",
                    "detail": "No repair was required; current functional evidence is healthy.",
                    "requires_operator": False,
                },
                "post_recovery_self_test": None,
                "post_recovery_state": snapshot.state.value,
                "fully_operational": True,
                "remaining_lost_capabilities": [],
                "pre_repair_snapshot": pre_repair,
                "repair_plan": repair_plan,
                "repair_trace": repair_trace,
                "errors": errors,
            }
            payload["copyable_transcript"] = render_surgical_repair_transcript(pre_repair, payload)
            return payload
        started = utc_now()
        trace("repair decision", "approved", f"Requesting bounded recovery for {snapshot.reason_code.value}; external blockers remain non-bypassable.")
        result = self.recovery.recover(provider, snapshot, self._policy(sensor_id), manual=True)
        trace(
            "bounded recovery",
            "succeeded" if result.succeeded else "not repaired",
            f"action={result.action.value}; attempted={result.attempted}; requires_operator={result.requires_operator}; detail={result.detail}",
        )
        if result.requires_operator:
            errors.append(f"OPERATOR_ACTION_REQUIRED: {result.detail or snapshot.remediation or snapshot.reason}")
        elif not result.succeeded:
            errors.append(f"RECOVERY_NOT_SUCCESSFUL: {result.detail or 'The recovery provider did not report success.'}")
        self.store.record_recovery(sensor_id, snapshot.reason_code.value, result, started_at=started)
        validation = self._bounded_self_test(provider, self._policy(sensor_id)) if result.succeeded else None
        if validation is None:
            trace("functional self-test", "not run", "Recovery did not succeed, so post-repair functional validation was not run.")
        else:
            trace("functional self-test", "passed" if validation.passed else "failed", f"test_id={validation.test_id}; {validation.reason}")
            if not validation.passed:
                errors.append(f"POST_REPAIR_SELF_TEST_FAILED [{validation.test_id}]: {validation.reason}")
        post_snapshot = self.evaluator.evaluate(provider.health_snapshot(), self._policy(sensor_id)) if result.succeeded else snapshot
        fully_operational = bool(
            result.succeeded
            and validation is not None
            and validation.passed
            and post_snapshot.state in healthy_states
            and not post_snapshot.lost_capabilities
        )
        trace(
            "independent post-repair snapshot",
            "verified" if fully_operational else "verification failed",
            f"state={post_snapshot.state.value}; remaining_lost_capabilities={','.join(post_snapshot.lost_capabilities) or 'none'}",
        )
        if not fully_operational and post_snapshot.lost_capabilities:
            errors.append("REMAINING_COVERAGE_LOSS: " + ", ".join(post_snapshot.lost_capabilities))
        if not fully_operational and post_snapshot.state not in healthy_states:
            errors.append(f"POST_REPAIR_STATE_NOT_HEALTHY: {post_snapshot.state.value} — {post_snapshot.reason}")
        payload = {
            "sensor_id": sensor_id,
            "reason_code": snapshot.reason_code.value,
            "recovery": {
                "attempted": result.attempted,
                "succeeded": result.succeeded,
                "action": result.action.value,
                "detail": result.detail,
                "requires_operator": result.requires_operator,
            },
            "post_recovery_self_test": None if validation is None else {"passed": validation.passed, "test_id": validation.test_id, "reason": validation.reason},
            "post_recovery_state": post_snapshot.state.value,
            "remaining_lost_capabilities": list(post_snapshot.lost_capabilities),
            "fully_operational": fully_operational,
            "pre_repair_snapshot": pre_repair,
            "post_repair_snapshot": post_snapshot.to_dict(),
            "repair_plan": repair_plan,
            "repair_trace": repair_trace,
            "errors": errors,
        }
        payload["copyable_transcript"] = render_surgical_repair_transcript(pre_repair, payload)
        return payload

    def recover_all_sensors(self) -> dict:
        """Repair each repairable sensor, then independently verify the platform."""

        initial = self.run_cycle(run_self_tests=False, auto_recover=False)
        candidates = [
            sensor.sensor_id
            for sensor in initial.sensors
            if sensor.state not in {SensorState.HEALTHY, SensorState.HEALTHY_IDLE, SensorState.DISABLED, SensorState.UNSUPPORTED}
            or sensor.lost_capabilities
        ]
        order = self._dependency_order(candidates)
        results: list[dict] = []
        for sensor_id in order:
            try:
                results.append(self.recover_sensor(sensor_id))
            except Exception as exc:
                detail = f"Recovery failed in isolation: {type(exc).__name__}: {exc}"
                sensor = {
                    "sensor_id": sensor_id,
                    "state": "REPAIR_FAILED",
                    "reason_code": "REPAIR_WORKFLOW_EXCEPTION",
                    "reason": detail,
                    "operator_action_required": True,
                }
                failure = {
                    "sensor_id": sensor_id,
                    "recovery": {
                        "attempted": False,
                        "succeeded": False,
                        "action": "OBSERVE",
                        "detail": detail,
                        "requires_operator": True,
                    },
                    "pre_repair_snapshot": sensor,
                    "repair_plan": build_surgical_repair_plan(sensor),
                    "repair_trace": [{"timestamp": utc_now().isoformat().replace("+00:00", "Z"), "stage": "workflow", "status": "exception", "detail": detail}],
                    "errors": [detail],
                    "fully_operational": False,
                }
                failure["copyable_transcript"] = render_surgical_repair_transcript(sensor, failure)
                results.append(failure)
        final_report = self.run_cycle(run_self_tests=True, auto_recover=False)
        fully_operational = bool(
            final_report.required_total > 0
            and final_report.required_healthy == final_report.required_total
            and final_report.overall_health.value == "HEALTHY"
        )
        return {
            "attempted_sensors": len(order),
            "verified_sensors": sum(bool(item.get("fully_operational")) for item in results),
            "operator_action_required": sum(bool((item.get("recovery") or {}).get("requires_operator")) for item in results),
            "fully_operational": fully_operational,
            "results": results,
            "final_report": final_report.to_dict(),
        }

    def _dependency_order(self, sensor_ids: list[str]) -> list[str]:
        selected = set(sensor_ids)
        descriptors = {item.sensor_id: item for item in self.registry.descriptors()}
        output: list[str] = []
        visiting: set[str] = set()

        def visit(sensor_id: str) -> None:
            if sensor_id in output or sensor_id in visiting:
                return
            visiting.add(sensor_id)
            descriptor = descriptors.get(sensor_id)
            if descriptor is not None:
                for dependency in descriptor.dependencies:
                    if dependency in selected:
                        visit(dependency)
            visiting.discard(sensor_id)
            output.append(sensor_id)

        for sensor_id in sensor_ids:
            visit(sensor_id)
        return output

    def _bounded_self_test(self, provider: SensorHealthProvider, policy: SensorHealthPolicy) -> SelfTestResult:
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="msaa-sensor-selftest")
        future = executor.submit(provider.perform_self_test)
        completed, _pending = wait((future,), timeout=policy.self_test_timeout_seconds)
        if not completed:
            future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            return SelfTestResult(False, "provider_self_test", "Self-test exceeded its bounded timeout.")
        try:
            return future.result()
        except Exception as exc:
            return SelfTestResult(False, "provider_self_test", f"Self-test failed in isolation: {type(exc).__name__}: {exc}")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _propagate_sensor_dependencies(self, snapshots: dict[str, SensorHealthSnapshot]) -> None:
        for descriptor in self.registry.descriptors():
            snapshot = snapshots.get(descriptor.sensor_id)
            if snapshot is None:
                continue
            dependencies = list(snapshot.dependencies)
            known_ids = {item.dependency_id for item in dependencies}
            for dependency_id in descriptor.dependencies:
                upstream = snapshots.get(dependency_id)
                if upstream is None or dependency_id in known_ids:
                    continue
                unhealthy = not upstream.process_alive or not upstream.initialized or upstream.state in {SensorState.FAILED, SensorState.UNAVAILABLE, SensorState.IMPAIRED}
                dependencies.append(SensorDependency(
                    dependency_id, True,
                    DependencyState.FAILED if unhealthy else DependencyState.HEALTHY,
                    f"shared sensor dependency state: {upstream.state.value}",
                    affected_capabilities=descriptor.capabilities,
                ))
            snapshots[descriptor.sensor_id] = replace(snapshot, dependencies=tuple(dependencies))

    def _policy(self, sensor_id: str) -> SensorHealthPolicy:
        return self.policies.get(sensor_id, policy_for(sensor_id))

    @staticmethod
    def _provider_failure(sensor_id: str, code: ReasonCode, reason: str) -> SensorHealthSnapshot:
        return SensorHealthSnapshot(sensor_id=sensor_id, process_alive=False, initialized=False, state=SensorState.FAILED,
                                    reason_code=code, reason=reason, operator_action_required=True,
                                    remediation="Inspect provider registration, timeout, and the external service watchdog without discarding evidence.")

    @staticmethod
    def _prior_snapshot(payload: dict | None) -> SensorHealthSnapshot | None:
        if not payload:
            return None
        try:
            return SensorHealthSnapshot(sensor_id=str(payload["sensor_id"]), state=SensorState(str(payload["state"])),
                                        health_score=int(payload.get("health_score", 0)), reason=str(payload.get("reason", "")))
        except (KeyError, TypeError, ValueError):
            return None


def default_coordinator(database: Path, *, system_database: Path | None = None, user_home: Path | None = None) -> SensorReliabilityCoordinator:
    from .providers import built_in_providers

    store = SensorHealthStore(database)
    registry = SensorRegistry.from_manifest()
    coordinator = SensorReliabilityCoordinator(store, registry)
    providers = built_in_providers(system_db=system_database or database, user_home=user_home, manager_state=coordinator.manager_state)
    coordinator.register(providers)
    return coordinator


__all__ = ["SensorReliabilityCoordinator", "default_coordinator"]

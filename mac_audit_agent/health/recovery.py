"""Bounded, evidence-preserving recovery decisions and circuit breakers."""

from __future__ import annotations

import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import (
    CircuitState, ReasonCode, RecoveryLevel, RecoveryReason, RecoveryResult,
    SensorHealthProvider, SensorHealthSnapshot,
)
from .policies import SensorHealthPolicy


NON_AUTOMATIC = {
    ReasonCode.PERMISSION_REVOKED, ReasonCode.PERMISSION_REQUIRED,
    ReasonCode.ENTITLEMENT_MISSING, ReasonCode.SIGNATURE_INVALID,
    ReasonCode.CONFIG_UNEXPECTED_CHANGE, ReasonCode.DISK_PRESSURE,
    ReasonCode.DUPLICATE_INSTANCE,
}

# These conditions cannot be repaired safely by retrying or restarting a
# process, even when the operator clicks Recover. They require a macOS,
# deployment, or evidence-preserving administrative workflow first.
EXTERNAL_REMEDIATION_REQUIRED = {
    ReasonCode.PERMISSION_REVOKED,
    ReasonCode.PERMISSION_REQUIRED,
    ReasonCode.ENTITLEMENT_MISSING,
    ReasonCode.SIGNATURE_INVALID,
    ReasonCode.DUPLICATE_INSTANCE,
}

RECOVERY_LADDER = {
    ReasonCode.IPC_DISCONNECTED: RecoveryLevel.RECONNECT,
    ReasonCode.HELPER_UNAVAILABLE: RecoveryLevel.RECONNECT,
    ReasonCode.DATABASE_LATENCY: RecoveryLevel.RECONNECT,
    ReasonCode.DATABASE_UNAVAILABLE: RecoveryLevel.RECONNECT,
    ReasonCode.RULE_LOAD_FAILURE: RecoveryLevel.REINITIALIZE,
    ReasonCode.PROCESSING_STALL: RecoveryLevel.RESTART_WORKER,
    ReasonCode.DELIVERY_STALL: RecoveryLevel.RESTART_WORKER,
    ReasonCode.PERSISTENCE_STALL: RecoveryLevel.RECONNECT,
    ReasonCode.EVENT_STREAM_STALE: RecoveryLevel.REINITIALIZE,
    ReasonCode.HEARTBEAT_STALE: RecoveryLevel.REQUEST_WATCHDOG,
    ReasonCode.PROCESS_NOT_RUNNING: RecoveryLevel.REQUEST_WATCHDOG,
}


@dataclass
class CircuitBreaker:
    state: CircuitState = CircuitState.CLOSED
    failures: int = 0
    opened_at: float = 0.0
    cool_down_seconds: float = 30.0

    def allow(self, now: float) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN and now - self.opened_at >= self.cool_down_seconds:
            self.state = CircuitState.HALF_OPEN
            return True
        return self.state == CircuitState.HALF_OPEN

    def success(self) -> None:
        self.state = CircuitState.CLOSED
        self.failures = 0

    def failure(self, now: float) -> None:
        self.failures += 1
        if self.failures >= 3:
            self.state = CircuitState.OPEN
            self.opened_at = now


class RecoveryEngine:
    def __init__(self, *, now=time.monotonic, random_source: random.Random | None = None) -> None:
        self.now = now
        self.random = random_source or random.Random()
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._circuits: dict[str, CircuitBreaker] = defaultdict(CircuitBreaker)

    def recover(self, provider: SensorHealthProvider, snapshot: SensorHealthSnapshot, policy: SensorHealthPolicy, *, manual: bool = False) -> RecoveryResult:
        code = snapshot.reason_code
        if code in EXTERNAL_REMEDIATION_REQUIRED:
            return RecoveryResult(
                False,
                False,
                RecoveryLevel.OPERATOR_REQUIRED,
                snapshot.remediation or snapshot.reason,
                requires_operator=True,
            )
        if code in NON_AUTOMATIC and not manual:
            return RecoveryResult(False, False, RecoveryLevel.OPERATOR_REQUIRED, snapshot.remediation or snapshot.reason, requires_operator=True)
        level = RECOVERY_LADDER.get(code, RecoveryLevel.OBSERVE)
        if level == RecoveryLevel.OBSERVE and not manual:
            return RecoveryResult(False, False, level, "No safe automatic recovery is defined for this condition.")
        now = self.now()
        attempts = self._attempts[snapshot.sensor_id]
        while attempts and now - attempts[0] > policy.restart_budget_window_seconds:
            attempts.popleft()
        if len(attempts) >= policy.restart_budget_count:
            return RecoveryResult(False, False, RecoveryLevel.OPERATOR_REQUIRED, "Restart budget exhausted; automatic retries are stopped.", requires_operator=True)
        circuit = self._circuits[snapshot.sensor_id]
        if not circuit.allow(now):
            return RecoveryResult(False, False, RecoveryLevel.OBSERVE, "Recovery circuit is open; waiting before a controlled half-open probe.")
        attempts.append(now)
        reason = RecoveryReason(code, snapshot.reason, level)
        try:
            result = provider.recover(reason)
        except Exception as exc:
            circuit.failure(now)
            return RecoveryResult(True, False, level, f"Recovery provider failed safely: {type(exc).__name__}: {exc}")
        if result.succeeded:
            circuit.success()
        elif result.attempted:
            circuit.failure(now)
        return result

    def backoff_seconds(self, sensor_id: str) -> float:
        count = max(0, len(self._attempts.get(sensor_id, ())) - 1)
        return min(60.0, (2**count) + self.random.uniform(0, 0.5))


__all__ = [
    "CircuitBreaker",
    "EXTERNAL_REMEDIATION_REQUIRED",
    "NON_AUTOMATIC",
    "RECOVERY_LADDER",
    "RecoveryEngine",
]

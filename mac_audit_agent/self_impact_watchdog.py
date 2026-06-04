from __future__ import annotations

import resource
import sys
import time
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SelfImpactMetrics:
    cycle_seconds: float
    poll_interval_seconds: float
    cpu_percent: float
    rss_mb: float
    emitted_events: int
    detector_errors: int


@dataclass(frozen=True)
class SelfImpactAssessment:
    score: int
    level: str
    sustained_warning: bool
    backoff_multiplier: int
    metrics: SelfImpactMetrics

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level,
            "sustained_warning": self.sustained_warning,
            "backoff_multiplier": self.backoff_multiplier,
            "metrics": asdict(self.metrics),
        }


class MonitorSelfImpactWatchdog:
    """Scores sustained audit-agent resource pressure without running collectors."""

    def __init__(self, *, alpha: float = 0.35) -> None:
        self.alpha = max(0.05, min(1.0, alpha))
        self._ewma_score = 0.0
        self._pressure_cycles = 0
        self._critical_cycles = 0
        self._previous_wall = time.monotonic()
        self._previous_cpu = self._cpu_seconds()
        self.last_assessment = SelfImpactAssessment(
            score=0,
            level="normal",
            sustained_warning=False,
            backoff_multiplier=1,
            metrics=SelfImpactMetrics(0.0, 0.0, 0.0, self._rss_mb(), 0, 0),
        )

    def collect_metrics(
        self,
        *,
        cycle_seconds: float,
        poll_interval_seconds: float,
        emitted_events: int,
        detector_errors: int,
    ) -> SelfImpactMetrics:
        wall = time.monotonic()
        cpu = self._cpu_seconds()
        elapsed = max(0.001, wall - self._previous_wall)
        cpu_percent = max(0.0, min(1000.0, ((cpu - self._previous_cpu) / elapsed) * 100.0))
        self._previous_wall = wall
        self._previous_cpu = cpu
        return SelfImpactMetrics(
            cycle_seconds=max(0.0, cycle_seconds),
            poll_interval_seconds=max(0.001, poll_interval_seconds),
            cpu_percent=cpu_percent,
            rss_mb=self._rss_mb(),
            emitted_events=max(0, emitted_events),
            detector_errors=max(0, detector_errors),
        )

    def evaluate(self, metrics: SelfImpactMetrics) -> SelfImpactAssessment:
        raw_score = self._raw_score(metrics)
        self._ewma_score = (self.alpha * raw_score) + ((1.0 - self.alpha) * self._ewma_score)
        score = min(100, max(0, round(self._ewma_score)))
        self._pressure_cycles = self._pressure_cycles + 1 if score >= 60 else 0
        self._critical_cycles = self._critical_cycles + 1 if score >= 80 else 0
        sustained_warning = self._critical_cycles >= 2 or self._pressure_cycles >= 3
        level = "critical" if sustained_warning else ("caution" if score >= 60 else "normal")
        backoff_multiplier = 4 if score >= 80 else (2 if score >= 60 else 1)
        self.last_assessment = SelfImpactAssessment(
            score=score,
            level=level,
            sustained_warning=sustained_warning,
            backoff_multiplier=backoff_multiplier,
            metrics=metrics,
        )
        return self.last_assessment

    def effective_poll_interval(self, base_seconds: float) -> float:
        return max(1.0, base_seconds) * self.last_assessment.backoff_multiplier

    @staticmethod
    def _raw_score(metrics: SelfImpactMetrics) -> float:
        cycle_ratio = metrics.cycle_seconds / max(0.001, metrics.poll_interval_seconds)
        cycle_score = min(35.0, cycle_ratio * 22.0)
        cpu_score = min(30.0, max(0.0, metrics.cpu_percent - 20.0) * 0.5)
        rss_score = min(15.0, max(0.0, metrics.rss_mb - 512.0) / 68.0)
        event_score = min(10.0, metrics.emitted_events / 2.0)
        error_score = min(10.0, metrics.detector_errors * 5.0)
        return cycle_score + cpu_score + rss_score + event_score + error_score

    @staticmethod
    def _cpu_seconds() -> float:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return float(usage.ru_utime + usage.ru_stime)

    @staticmethod
    def _rss_mb() -> float:
        rss = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # macOS reports bytes; Linux and several BSD test environments report KiB.
        divisor = 1024.0 * 1024.0 if sys.platform == "darwin" else 1024.0
        return rss / divisor

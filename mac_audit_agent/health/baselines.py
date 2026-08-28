"""Bounded rolling statistics for workload-aware sensor health baselines."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from math import sqrt
from statistics import mean, median


@dataclass(frozen=True)
class BaselineSummary:
    samples: int
    moving_average: float
    moving_stddev: float
    p50: float
    p95: float
    p99: float


class RollingBaseline:
    def __init__(self, max_samples: int = 360) -> None:
        if not 10 <= max_samples <= 100_000:
            raise ValueError("rolling baseline sample bound must be between 10 and 100000")
        self.values: deque[float] = deque(maxlen=max_samples)

    def add(self, value: float) -> None:
        value = float(value)
        if value < 0 or value != value or value == float("inf"):
            raise ValueError("baseline metric must be finite and non-negative")
        self.values.append(value)

    def summary(self) -> BaselineSummary:
        if not self.values:
            return BaselineSummary(0, 0, 0, 0, 0, 0)
        ordered = sorted(self.values)
        average = mean(ordered)
        deviation = sqrt(sum((item - average) ** 2 for item in ordered) / len(ordered))
        percentile = lambda fraction: ordered[min(len(ordered) - 1, round((len(ordered) - 1) * fraction))]
        return BaselineSummary(len(ordered), average, deviation, median(ordered), percentile(0.95), percentile(0.99))

    def classify(self, value: float, *, minimum_samples: int = 20, sigma: float = 4.0) -> str:
        summary = self.summary()
        if summary.samples < minimum_samples:
            return "LEARNING"
        if value > max(summary.p99 * 2, summary.moving_average + sigma * summary.moving_stddev):
            return "SIGNIFICANT_DEVIATION"
        return "WITHIN_BASELINE"


__all__ = ["BaselineSummary", "RollingBaseline"]

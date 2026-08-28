"""Performance profiles with bounded defaults."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PerformanceProfile:
    name: str
    queue_size: int
    batch_size: int
    sample_bytes: int
    cpu_budget_percent: int


PROFILES = {
    "low_impact": PerformanceProfile("Low Impact", 512, 64, 16384, 5),
    "balanced": PerformanceProfile("Balanced", 2048, 128, 65536, 10),
    "thorough": PerformanceProfile("Thorough", 4096, 256, 131072, 20),
    "incident_response": PerformanceProfile("Incident Response", 8192, 512, 262144, 35),
}

__all__ = ["PROFILES", "PerformanceProfile"]

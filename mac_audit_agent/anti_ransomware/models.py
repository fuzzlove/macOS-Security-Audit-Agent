from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.compat.enum import StrEnum

SCHEMA_VERSION = "1.0"


class ProtectionMode(StrEnum):
    OBSERVE = "OBSERVE"
    BALANCED = "BALANCED_PROTECTION"
    HIGH_ASSURANCE = "HIGH_ASSURANCE"
    ADAPTIVE = "ADAPTIVE_BEHAVIOR"
    COMPATIBILITY = "RANSOMWHERE_COMPAT"


class SensorMode(StrEnum):
    NONE = "NONE"
    SAFE_SIMULATION_ONLY = "SAFE_SIMULATION_ONLY"
    DEGRADED_OBSERVATION_ONLY = "DEGRADED_OBSERVATION_ONLY"
    EXTERNAL_TELEMETRY_OBSERVATION = "EXTERNAL_TELEMETRY_OBSERVATION"
    ENDPOINT_SECURITY_NOTIFY_ONLY = "ENDPOINT_SECURITY_NOTIFY_ONLY"
    ENDPOINT_SECURITY_AUTH_AND_NOTIFY = "ENDPOINT_SECURITY_AUTH_AND_NOTIFY"
    ENDPOINT_SECURITY = "ENDPOINT_SECURITY_AUTH_AND_NOTIFY"


class HealthState(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"
    MISCONFIGURED = "MISCONFIGURED"
    TAMPERED = "TAMPERED"
    CRASH_LOOP = "CRASH_LOOP"
    EVENT_LOSS_DETECTED = "EVENT_LOSS_DETECTED"
    PERMISSION_REQUIRED = "PERMISSION_REQUIRED"
    NOT_APPLICABLE_NO_GUI_SESSION = "NOT_APPLICABLE_NO_GUI_SESSION"
    NOT_VERIFIED = "NOT_VERIFIED"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pid_version: int
    executable_path: str
    executable_sha256: str
    effective_uid: int
    boot_session_id: str
    parent_pid: int | None = None
    responsible_pid: int | None = None
    signing_id: str = ""
    team_id: str = ""
    script_path: str = ""
    script_sha256: str = ""
    platform_binary: bool = False
    notarized: bool | None = None
    audit_token_hash: str = ""
    executable_file_id: str = ""
    cdhash: str = ""
    process_start_time_ns: int = 0

    @property
    def stable_key(self) -> str:
        return f"{self.boot_session_id}:{self.pid}:{self.pid_version}:{self.effective_uid}:{self.executable_sha256}:{self.script_sha256}"

    def matches_exact(self, other: ProcessIdentity) -> bool:
        required = (
            "pid", "pid_version", "effective_uid", "boot_session_id", "executable_path",
            "executable_sha256", "script_path", "script_sha256", "audit_token_hash",
            "executable_file_id", "cdhash", "process_start_time_ns",
        )
        return all(getattr(self, field) == getattr(other, field) for field in required)


@dataclass(frozen=True)
class FileStatistics:
    size: int
    entropy: float
    chi_square: float
    monte_carlo_pi_error: float
    base64_ratio: float
    recognized_image: bool
    gzip_header: bool
    bytes_sampled: int


@dataclass(frozen=True)
class FileMutation:
    event_id: str
    timestamp: float
    process: ProcessIdentity
    path_token: str
    operation: str
    statistics: FileStatistics


@dataclass(frozen=True)
class DetectionSignal:
    signal_id: str
    weight: int
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionDecision:
    decision_id: str
    score: int
    confidence: str
    severity: str
    recommended_response: str
    automatic_response_eligible: bool
    signals: tuple[DetectionSignal, ...]
    policy_version: str = "1.0"
    ruleset_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RCEConfig:
    schema_version: str = "1.0"
    enabled: bool = True
    sensitivity: str = "high"
    monitor_only: bool = True
    queue_limit: int = 2048
    correlation_window_seconds: int = 30
    correlation_windows_seconds: tuple[int, ...] = (5, 30, 120, 300)
    operation_mode: str = "NORMAL"
    suspected_threshold: int = 55
    probable_threshold: int = 80
    duplicate_window_seconds: int = 300
    max_representative_evidence: int = 20
    cve_freshness_hours: int = 168
    inventory_interval_seconds: int = 3600
    event_retention_days: int = 180
    raw_evidence_retention_days: int = 30
    allowed_management_uids: tuple[int, ...] = (0,)
    redacted_environment_keys: tuple[str, ...] = ("PASSWORD", "TOKEN", "SECRET", "KEY", "COOKIE", "AUTH")
    attack_data_path: str = ""
    cve_cache_path: str = ""
    enabled_sensors: tuple[str, ...] = ("process_poll", "network_snapshot", "file_metadata", "package_inventory")
    framework_versions: dict[str, str] = field(default_factory=dict)
    injection_correlation_window_seconds: int = 30
    injection_novelty_threshold: int = 60
    injection_similarity_threshold: int = 50
    evidence_capture_tier: int = 1
    tier2_memory_capture_enabled: bool = False
    evidence_max_bytes: int = 8 * 1024 * 1024
    evidence_encryption_required: bool = False
    protected_process_categories: tuple[str, ...] = ("credentials", "identity", "classified", "regulated")
    attack_freshness_hours: int = 720

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RCEConfig":
        if payload.get("schema_version") != "1.0":
            raise ValueError("unsupported RCE configuration schema")
        sensitivity = str(payload.get("sensitivity", "high"))
        if sensitivity not in {"high", "balanced"}:
            raise ValueError("sensitivity must be high or balanced")
        queue_limit = int(payload.get("queue_limit", 2048))
        if not 32 <= queue_limit <= 100_000:
            raise ValueError("queue_limit outside safe bounds")
        mode = str(payload.get("operation_mode", "NORMAL")).upper()
        if mode not in {"NORMAL", "RESEARCH", "FUZZING", "DEVELOPMENT"}:
            raise ValueError("operation_mode must be NORMAL, RESEARCH, FUZZING, or DEVELOPMENT")
        windows = tuple(sorted({max(1, min(int(value), 600)) for value in payload.get("correlation_windows_seconds", [5, 30, 120, 300])}))
        suspected = max(20, min(int(payload.get("suspected_threshold", 55)), 90))
        probable = max(suspected + 1, min(int(payload.get("probable_threshold", 80)), 100))
        return cls(
            schema_version="1.0", enabled=bool(payload.get("enabled", True)),
            sensitivity=sensitivity, monitor_only=bool(payload.get("monitor_only", True)),
            queue_limit=queue_limit,
            correlation_window_seconds=max(1, min(int(payload.get("correlation_window_seconds", 30)), 600)),
            correlation_windows_seconds=windows or (5, 30, 120, 300),
            operation_mode=mode,
            suspected_threshold=suspected,
            probable_threshold=probable,
            duplicate_window_seconds=max(1, min(int(payload.get("duplicate_window_seconds", 300)), 86_400)),
            max_representative_evidence=max(1, min(int(payload.get("max_representative_evidence", 20)), 100)),
            cve_freshness_hours=max(1, min(int(payload.get("cve_freshness_hours", 168)), 8760)),
            inventory_interval_seconds=max(60, int(payload.get("inventory_interval_seconds", 3600))),
            event_retention_days=max(1, int(payload.get("event_retention_days", 180))),
            raw_evidence_retention_days=max(1, int(payload.get("raw_evidence_retention_days", 30))),
            allowed_management_uids=tuple(int(v) for v in payload.get("allowed_management_uids", [0])),
            redacted_environment_keys=tuple(str(v).upper() for v in payload.get("redacted_environment_keys", cls.redacted_environment_keys)),
            attack_data_path=str(payload.get("attack_data_path", "")), cve_cache_path=str(payload.get("cve_cache_path", "")),
            enabled_sensors=tuple(str(v) for v in payload.get("enabled_sensors", cls.enabled_sensors)),
            framework_versions={str(k): str(v) for k, v in dict(payload.get("framework_versions", {})).items()},
            injection_correlation_window_seconds=max(1,min(int(payload.get("injection_correlation_window_seconds",30)),600)),
            injection_novelty_threshold=max(0,min(int(payload.get("injection_novelty_threshold",60)),100)),
            injection_similarity_threshold=max(0,min(int(payload.get("injection_similarity_threshold",50)),100)),
            evidence_capture_tier=max(0,min(int(payload.get("evidence_capture_tier",1)),3)),
            tier2_memory_capture_enabled=bool(payload.get("tier2_memory_capture_enabled",False)),
            evidence_max_bytes=max(1024,min(int(payload.get("evidence_max_bytes",8*1024*1024)),128*1024*1024)),
            evidence_encryption_required=bool(payload.get("evidence_encryption_required",False)),
            protected_process_categories=tuple(str(v) for v in payload.get("protected_process_categories",cls.protected_process_categories)),
            attack_freshness_hours=max(1,min(int(payload.get("attack_freshness_hours",720)),8760)),
        )


def load_rce_config(path: Path | None) -> RCEConfig:
    if path is None or not path.exists():
        return RCEConfig()
    if path.stat().st_size > 1_048_576:
        raise ValueError("RCE configuration exceeds 1 MiB")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("RCE configuration must be an object")
    return RCEConfig.from_dict(payload)

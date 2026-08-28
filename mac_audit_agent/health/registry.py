"""Expected sensor manifest and bounded dynamic provider registration."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Criticality, SensorDescriptor, SensorHealthProvider


SENSOR_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "assets" / "sensor_manifest.json"


DEFAULT_DESCRIPTORS = (
    SensorDescriptor("endpoint_security", "Endpoint Security", Criticality.CRITICAL, capabilities=("process_execution", "file_modification", "ransomware_telemetry"), dependencies=("endpoint_security_client", "full_disk_access", "signed_sensor"), failure_domain="Endpoint Security"),
    SensorDescriptor("ransomware_monitor", "Ransomware Monitor", Criticality.CRITICAL, capabilities=("ransomware_detection", "ransomware_evidence"), dependencies=("endpoint_security", "evidence_database", "ruleset"), failure_domain="Endpoint Security"),
    SensorDescriptor("system_monitor", "System Monitor", Criticality.HIGH, capabilities=("system_activity", "event_correlation", "evidence_persistence"), dependencies=("sqlite",), failure_domain="Database"),
    SensorDescriptor("behavioral_telemetry", "Behavioral Telemetry", Criticality.HIGH, capabilities=("behavioral_aggregation", "behavioral_baseline", "anomaly_detection"), dependencies=("system_monitor", "sqlite"), failure_domain="Behavioral Analytics"),
    SensorDescriptor("malware_definitions", "Malware Definitions", Criticality.HIGH, capabilities=("malware_hash_matching", "malware_rule_matching", "definition_provenance"), dependencies=("definition_store", "ruleset"), failure_domain="Definition Management"),
    SensorDescriptor("user_notifier", "User Alert Agent", Criticality.HIGH, capabilities=("critical_alert_delivery",), dependencies=("user_session", "notification_permission", "sqlite"), failure_domain="User Interface"),
    SensorDescriptor("sensor_health_manager", "Sensor Health Manager", Criticality.CRITICAL, capabilities=("sensor_health_assurance",), dependencies=("sqlite",), failure_domain="Health Assurance"),
    SensorDescriptor("yara_engine", "YARA Rule Engine", Criticality.MEDIUM, expected=False, enabled=False, capabilities=("malware_rule_matching",), dependencies=("ruleset",), failure_domain="Rule Engine"),
)


class SensorRegistry:
    def __init__(self, descriptors: tuple[SensorDescriptor, ...] | None = None) -> None:
        self._descriptors = {item.sensor_id: item for item in (descriptors or DEFAULT_DESCRIPTORS)}
        self._providers: dict[str, SensorHealthProvider] = {}

    @classmethod
    def from_manifest(cls, path: Path = DEFAULT_MANIFEST_PATH) -> "SensorRegistry":
        if not path.is_file():
            return cls()
        payload = json.loads(path.read_text(encoding="utf-8"))
        descriptors: list[SensorDescriptor] = []
        for expected, enabled_default in (("required", True), ("optional", False)):
            for item in payload.get(expected, []):
                descriptors.append(SensorDescriptor(
                    sensor_id=str(item["sensor_id"]),
                    display_name=str(item.get("display_name") or item["sensor_id"]),
                    criticality=Criticality(str(item.get("criticality", "MEDIUM"))),
                    expected=expected == "required",
                    enabled=bool(item.get("enabled", enabled_default)),
                    singleton=bool(item.get("singleton", True)),
                    capabilities=tuple(str(value) for value in item.get("capabilities", [])),
                    dependencies=tuple(str(value) for value in item.get("dependencies", [])),
                    failure_domain=str(item.get("failure_domain", "general")),
                ))
        return cls(tuple(descriptors))

    def register(self, provider: SensorHealthProvider) -> None:
        sensor_id = str(provider.sensor_id())
        if not SENSOR_ID_PATTERN.fullmatch(sensor_id):
            raise ValueError(f"invalid sensor identifier: {sensor_id!r}")
        if sensor_id not in self._descriptors:
            raise ValueError(f"sensor {sensor_id!r} is not declared in the expected manifest")
        if sensor_id in self._providers:
            raise ValueError(f"duplicate sensor provider: {sensor_id}")
        self._providers[sensor_id] = provider

    def descriptor(self, sensor_id: str) -> SensorDescriptor:
        return self._descriptors[sensor_id]

    def descriptors(self) -> tuple[SensorDescriptor, ...]:
        return tuple(self._descriptors.values())

    def providers(self) -> tuple[SensorHealthProvider, ...]:
        return tuple(self._providers.values())

    def provider(self, sensor_id: str) -> SensorHealthProvider | None:
        return self._providers.get(sensor_id)

    def missing_expected(self) -> tuple[SensorDescriptor, ...]:
        return tuple(item for item in self._descriptors.values() if item.expected and item.enabled and item.sensor_id not in self._providers)


__all__ = ["DEFAULT_DESCRIPTORS", "DEFAULT_MANIFEST_PATH", "SensorRegistry"]

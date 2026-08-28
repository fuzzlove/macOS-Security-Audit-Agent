from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from itertools import count
from typing import Iterable

from mac_audit_agent.models import BackgroundMonitorEvent


def telemetry_event(
    timestamp: datetime,
    event_type: str,
    *,
    process: str = "",
    path: str = "",
    endpoint: str = "",
    user: str = "demo-user",
    metadata: dict | None = None,
    severity: str = "info",
    sequence: int = 0,
) -> BackgroundMonitorEvent:
    stamp = _utc(timestamp).isoformat()
    return BackgroundMonitorEvent(
        event_id=f"synthetic-{int(_utc(timestamp).timestamp())}-{sequence}-{event_type}",
        timestamp=stamp,
        event_type=event_type,
        severity=severity,
        source="synthetic_security_fixture",
        process_name=process,
        related_process=process,
        related_path=path,
        related_network_endpoint=endpoint,
        related_user=user,
        evidence="Synthetic defensive telemetry fixture; no executable content.",
        confidence="medium",
        metadata_json=json.dumps({"user_uid": 501, "process_name": process, "process_path": path, **(metadata or {})}, sort_keys=True),
    )


def normal_workday(
    start: datetime,
    *,
    buckets: int = 24,
    process_events: int = 4,
    network_events: int = 2,
    dns_events: int = 3,
    user: str = "demo-user",
) -> list[BackgroundMonitorEvent]:
    """Deterministic content-free routine suitable for golden fixtures."""
    events: list[BackgroundMonitorEvent] = []
    sequence = count()
    for bucket in range(buckets):
        base = _utc(start) + timedelta(minutes=5 * bucket)
        for index in range(process_events):
            events.append(telemetry_event(base + timedelta(seconds=index), "process_execution", process="Safari", path="/Applications/Safari.app/Contents/MacOS/Safari", user=user, metadata={"signing_status": "apple"}, sequence=next(sequence)))
        for index in range(network_events):
            events.append(telemetry_event(base + timedelta(seconds=10 + index), "network_connection", process="Safari", endpoint="routine.example:443", user=user, sequence=next(sequence)))
        for index in range(dns_events):
            events.append(telemetry_event(base + timedelta(seconds=20 + index), "dns_query", process="Safari", metadata={"domain": "routine.example"}, user=user, sequence=next(sequence)))
    return events


def developer_workstation(start: datetime, *, buckets: int = 24) -> list[BackgroundMonitorEvent]:
    events = normal_workday(start, buckets=buckets, process_events=8, network_events=4, dns_events=4)
    sequence = count(len(events))
    for bucket in range(buckets):
        base = _utc(start) + timedelta(minutes=5 * bucket, seconds=30)
        events.append(telemetry_event(base, "process_execution", process="python3", path="/usr/bin/python3", metadata={"parent_process": "zsh", "signing_status": "apple"}, sequence=next(sequence)))
    return events


def office_user(start: datetime, *, buckets: int = 24) -> list[BackgroundMonitorEvent]:
    return normal_workday(start, buckets=buckets, process_events=3, network_events=2, dns_events=2)


def server_like_activity(start: datetime, *, buckets: int = 24) -> list[BackgroundMonitorEvent]:
    return normal_workday(start, buckets=buckets, process_events=10, network_events=8, dns_events=1, user="service-account")


def research_workstation(start: datetime, *, buckets: int = 24) -> list[BackgroundMonitorEvent]:
    events = developer_workstation(start, buckets=buckets)
    for event in events:
        metadata = json.loads(event.metadata_json)
        metadata["research_mode"] = True
        event.metadata_json = json.dumps(metadata, sort_keys=True)
    return events


def process_storm(start: datetime, *, count_value: int = 100) -> list[BackgroundMonitorEvent]:
    return [telemetry_event(start + timedelta(milliseconds=index), "process_execution", process=f"worker-{index % 5}", path="/usr/bin/true", metadata={"signing_status": "apple"}, sequence=index) for index in range(count_value)]


def network_storm(start: datetime, *, count_value: int = 100) -> list[BackgroundMonitorEvent]:
    return [telemetry_event(start + timedelta(milliseconds=index), "network_connection", process="python3", endpoint=f"192.0.2.{index % 250}:443", sequence=index) for index in range(count_value)]


def authentication_anomaly(start: datetime) -> list[BackgroundMonitorEvent]:
    return [telemetry_event(start + timedelta(seconds=index), "failed_authentication", user="unexpected-user", severity="medium", sequence=index) for index in range(20)]


def persistence_incident(start: datetime) -> list[BackgroundMonitorEvent]:
    return [telemetry_event(start, "launchagent_added", process="unknown-helper", path="/Users/demo/Library/LaunchAgents/example.plist", metadata={"first_seen": True, "signing_status": "unsigned"}, severity="high")]


def ransomware_like_behavior(start: datetime) -> list[BackgroundMonitorEvent]:
    events: list[BackgroundMonitorEvent] = []
    for index in range(80):
        events.append(telemetry_event(start + timedelta(milliseconds=index * 10), "file_rename", process="fixture-encryptor", path=f"/Users/demo/Documents/file-{index}.fixture", metadata={"first_seen": True, "signing_status": "unsigned"}, severity="medium", sequence=index))
    return events


def required_demonstration(start: datetime | None = None) -> dict[str, list[BackgroundMonitorEvent]]:
    """Mission scenario: a calm period followed by one correlated incident."""
    day = _utc(start or datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc))
    history: list[BackgroundMonitorEvent] = []
    # Same weekday/hour cohorts over prior weeks establish time-aware behavior
    # without contaminating the demonstration period.
    for prior_week in range(35, 0, -1):
        historical_start = day - timedelta(days=7 * prior_week)
        history.extend(normal_workday(historical_start, buckets=24))
    normal = normal_workday(day, buckets=24)
    suspicious_path = "/Users/demo/Downloads/update-helper"
    sequence = count(100_000)
    deviation = [
        telemetry_event(day.replace(hour=11, minute=5), "process_execution", process="update-helper", path=suspicious_path, metadata={"first_seen": True, "signing_status": "unsigned"}, severity="medium", sequence=next(sequence)),
    ]
    burst = day.replace(hour=11, minute=6)
    for index in range(16):
        deviation.append(telemetry_event(burst + timedelta(seconds=index), "process_execution", process="update-helper", path=suspicious_path, metadata={"first_seen": True, "signing_status": "unsigned", "parent_process": "zsh"}, severity="medium", sequence=next(sequence)))
    for index in range(6):
        deviation.append(telemetry_event(burst + timedelta(seconds=20 + index), "network_connection", process="update-helper", path=suspicious_path, endpoint=f"198.51.100.{10 + index}:443", metadata={"first_seen": True, "signing_status": "unsigned"}, severity="medium", sequence=next(sequence)))
    deviation.extend([
        telemetry_event(day.replace(hour=11, minute=7), "launchagent_added", process="update-helper", path=suspicious_path, metadata={"first_seen": True, "signing_status": "unsigned"}, severity="high", sequence=next(sequence)),
        telemetry_event(day.replace(hour=11, minute=7, second=15), "privilege_elevation", process="update-helper", path=suspicious_path, metadata={"first_seen": True, "signing_status": "unsigned", "privileged": True, "effective_uid": 0}, severity="high", sequence=next(sequence)),
    ])
    return {"history": history, "normal": normal, "deviation": deviation}


def iter_profiles(start: datetime) -> Iterable[tuple[str, list[BackgroundMonitorEvent]]]:
    yield "normal_workday", normal_workday(start)
    yield "developer_workstation", developer_workstation(start)
    yield "office_user", office_user(start)
    yield "server_like_activity", server_like_activity(start)
    yield "research_workstation", research_workstation(start)
    yield "process_storm", process_storm(start)
    yield "network_storm", network_storm(start)
    yield "authentication_anomaly", authentication_anomaly(start)
    yield "persistence_incident", persistence_incident(start)
    yield "ransomware_like_behavior", ransomware_like_behavior(start)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


__all__ = [
    "authentication_anomaly", "developer_workstation", "iter_profiles", "network_storm", "normal_workday",
    "office_user", "persistence_incident", "process_storm", "ransomware_like_behavior", "required_demonstration",
    "research_workstation", "server_like_activity", "telemetry_event",
]

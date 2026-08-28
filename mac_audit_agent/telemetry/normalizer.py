from __future__ import annotations

import json
import socket
import time
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.telemetry.models import ActivityDimension, AnalyticsAvailability, NormalizedTelemetryEvent
from mac_audit_agent.telemetry.privacy import minimize_mapping, stable_reference, user_reference


DETERMINISTIC_EXCLUSION_TYPES = {
    "behavioral_anomaly", "behavioral_incident", "monitor_test_event", "monitor_self_test",
}


class TelemetryNormalizer:
    """Convert canonical MSAA events into bounded, content-free behavioral features."""

    def __init__(self, *, host_ref: str | None = None, host_salt: str | None = None) -> None:
        hostname = socket.gethostname()
        self.host_salt = host_salt or hostname
        self.host_ref = host_ref or stable_reference("host", hostname, self.host_salt)

    def normalize(self, event: BackgroundMonitorEvent | dict[str, Any], *, monotonic_timestamp: float | None = None) -> NormalizedTelemetryEvent | None:
        payload = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        event_type = str(payload.get("event_type") or "").strip().lower()
        if not event_type or event_type in DETERMINISTIC_EXCLUSION_TYPES or str(payload.get("source") or "").startswith("behavioral_telemetry"):
            return None
        metadata = self._metadata(payload.get("metadata_json"))
        dimension, features = self._features(event_type, payload, metadata)
        if dimension is None or not features:
            return None
        uid = metadata.get("user_uid")
        uid_value = int(uid) if isinstance(uid, int) or str(uid or "").isdigit() else None
        account = str(payload.get("related_user") or metadata.get("user_name") or "")
        user_ref = user_reference(uid=uid_value, account=account, host_salt=self.host_salt)
        user_class = self._user_class(uid_value, metadata)
        process = str(payload.get("related_process") or payload.get("process_name") or metadata.get("process_name") or "")
        path = str(payload.get("related_path") or metadata.get("process_path") or "")
        remote = str(payload.get("related_network_endpoint") or metadata.get("remote_address") or "")
        domain = str(metadata.get("domain") or metadata.get("query_name") or "")
        parent = str(metadata.get("parent_process") or "")
        signing_identifier = str(metadata.get("signing_identifier") or "")
        team_identifier = str(metadata.get("team_identifier") or metadata.get("team_id") or "")
        remote_asn = str(metadata.get("remote_asn") or metadata.get("asn") or "")
        entity_values = {
            "process": process,
            "path": path,
            "destination": remote,
            "domain": domain,
            "signing_identifier": signing_identifier,
            "team_identifier": team_identifier,
            "remote_asn": remote_asn,
            "process_parent_edge": f"{parent}->{process}" if parent and process else "",
        }
        entities = {
            key: stable_reference(key, value, self.host_salt)
            for key, value in entity_values.items()
            if value
        }
        signing = str(metadata.get("signing_status") or metadata.get("signature_status") or "").lower()
        behavior_traits = self._behavior_traits(event_type, process, path, signing, user_class, metadata)
        context = minimize_mapping(
            {
                "severity": payload.get("severity", "info"),
                "confidence": payload.get("confidence", "low"),
                "signed": signing not in {"unsigned", "invalid", "ad_hoc"} if signing else None,
                "unsigned": signing in {"unsigned", "invalid", "ad_hoc"},
                "privileged": bool(metadata.get("privileged") or uid_value == 0),
                "first_seen": bool(metadata.get("first_seen") or payload.get("baseline_status") in {"new", "first_seen"}),
                "downloads_path": "/Downloads/" in path,
                "temporary_path": path.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")),
                "known_malicious": bool(metadata.get("known_malicious") or metadata.get("ioc_match") or metadata.get("yara_match")),
                "maintenance_context": str(metadata.get("maintenance_context") or ""),
                "research_mode": bool(metadata.get("research_mode")),
                "simulated": bool(payload.get("simulated")),
                "parent_process": parent,
                "coverage_overrides": metadata.get("coverage_overrides") or {},
                "behavior_traits": behavior_traits,
            }
        )
        raw_coverage = str(metadata.get("telemetry_coverage") or "VALID").upper()
        try:
            coverage = AnalyticsAvailability(raw_coverage)
        except ValueError:
            coverage = AnalyticsAvailability.UNKNOWN
        eligible = not bool(context.get("known_malicious")) and str(payload.get("severity", "")).lower() != "critical" and not bool(context.get("simulated"))
        return NormalizedTelemetryEvent(
            event_id=str(payload.get("event_id") or ""), timestamp=str(payload.get("timestamp") or ""),
            monotonic_timestamp=float(monotonic_timestamp if monotonic_timestamp is not None else time.monotonic()),
            host_ref=self.host_ref, user_ref=user_ref, user_class=user_class, dimension=dimension,
            event_name=event_type, features=features, entity_keys=entities, security_context=context,
            evidence_refs=(str(payload.get("event_id") or ""),), sensor_id=str(payload.get("source") or "system_monitor"),
            coverage=coverage, baseline_training_eligible=eligible,
        )

    @staticmethod
    def _behavior_traits(
        event_type: str,
        process: str,
        path: str,
        signing: str,
        user_class: str,
        metadata: dict[str, Any],
    ) -> list[str]:
        searchable = f"{event_type} {process} {path}".lower()
        traits: list[str] = []
        if any(token in searchable for token in ("xcode", "clang", "gcc", "make", "python", "node", "ruby", "swift", "zsh", "bash")):
            traits.append("DEVELOPMENT_TOOLING")
        if bool(metadata.get("research_mode")) or any(token in searchable for token in ("research_", "malware_lab", "rule_test")):
            traits.append("RESEARCH_ACTIVITY")
        if bool(metadata.get("fuzzing")) or bool(metadata.get("debugger_attached")) or any(token in searchable for token in ("fuzz", "lldb", "debugger")):
            traits.append("FUZZING_ACTIVITY")
        if user_class == "service" or any(token in event_type for token in ("listener", "daemon_started", "service_started")):
            traits.append("SERVER_SERVICE_ACTIVITY")
        if signing in {"unsigned", "invalid", "ad_hoc"}:
            traits.append("UNSIGNED_EXECUTION")
        if path.startswith(("/tmp/", "/private/tmp/", "/var/tmp/")):
            traits.append("TEMPORARY_EXECUTION")
        if "/Downloads/" in path:
            traits.append("DOWNLOAD_EXECUTION")
        if any(token in event_type for token in ("remote_login", "remote_access", "ssh_login", "screen_sharing")):
            traits.append("REMOTE_ACCESS")
        if any(token in event_type for token in ("usb_", "bluetooth_", "physical_device")):
            traits.append("EXTERNAL_DEVICE_ACTIVITY")
        return list(dict.fromkeys(traits))

    @staticmethod
    def _metadata(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        try:
            parsed = json.loads(str(value or "{}"))
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _user_class(uid: int | None, metadata: dict[str, Any]) -> str:
        declared = str(metadata.get("user_class") or "").lower()
        if declared in {"interactive", "system", "service", "unknown"}:
            return declared
        if uid is None:
            return "unknown"
        return "system" if uid == 0 else "service" if uid < 500 else "interactive"

    @staticmethod
    def _features(event_type: str, payload: dict[str, Any], metadata: dict[str, Any]) -> tuple[ActivityDimension | None, dict[str, float]]:
        # Each call represents one canonical ingress receipt. Duplicate
        # consolidation maintains its own cumulative occurrence count, which
        # must not be re-added or telemetry volume would grow quadratically.
        count = 1.0
        if any(token in event_type for token in ("process", "execution", "shell", "interpreter")):
            features = {"process_exec_count": count, "unique_process_count": 1.0}
            if metadata.get("first_seen") or payload.get("baseline_status") in {"new", "first_seen"}: features["first_seen_process_count"] = 1.0
            if str(metadata.get("signing_status") or metadata.get("signature_status") or "").lower() in {"unsigned", "invalid", "ad_hoc"}: features["unsigned_process_count"] = 1.0
            if bool(metadata.get("privileged")) or metadata.get("effective_uid") == 0: features["privileged_execution_count"] = 1.0
            return ActivityDimension.PROCESS, features
        if any(token in event_type for token in ("network", "connection", "listener", "port_", "vpn_")):
            return ActivityDimension.NETWORK, {"network_connection_count": count, "unique_destination_count": 1.0}
        if "dns" in event_type or "resolver" in event_type:
            return ActivityDimension.DNS, {"dns_query_count": count, "unique_domain_count": 1.0, **({"dns_resolver_change_count": 1.0} if "server" in event_type or "resolver" in event_type else {})}
        if any(token in event_type for token in ("file_", "rename", "delete", "write", "entropy")):
            return ActivityDimension.FILESYSTEM, {"filesystem_event_count": count}
        if any(token in event_type for token in ("launchagent", "launchdaemon", "login_item", "persistence", "startup")):
            return ActivityDimension.PERSISTENCE, {"persistence_change_count": count}
        if any(token in event_type for token in ("login", "logout", "unlock", "authentication", "session_", "admin_user")):
            features = {"authentication_event_count": count}
            if "failed" in event_type: features["authentication_failure_count"] = count
            if "new_admin" in event_type: features["new_administrator_count"] = count
            return ActivityDimension.AUTHENTICATION, features
        if any(token in event_type for token in ("privilege", "sudo", "root_", "administrator")):
            return ActivityDimension.PRIVILEGE, {"privileged_execution_count": count}
        if any(token in event_type for token in ("firewall", "filevault", "gatekeeper", "security_configuration", "remote_login", "sharing_", "proxy", "profile")):
            return ActivityDimension.SECURITY_CONFIGURATION, {"security_setting_change_count": count}
        if any(token in event_type for token in ("application_installed", "application_removed", "package_installed", "software_")):
            return ActivityDimension.SOFTWARE, {"software_installation_count": count}
        if any(token in event_type for token in ("usb_", "bluetooth_", "physical_device")):
            return ActivityDimension.EXTERNAL_DEVICE, {"external_device_event_count": count}
        if any(token in event_type for token in ("sensor", "detector", "heartbeat", "monitor_", "notifier", "tamper")):
            return ActivityDimension.SENSOR, {"sensor_security_tool_event_count": count}
        if any(token in event_type for token in ("application", "app_")):
            return ActivityDimension.APPLICATION, {"application_event_count": count}
        return None, {}


__all__ = ["TelemetryNormalizer"]

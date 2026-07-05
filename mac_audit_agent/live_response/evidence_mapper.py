from __future__ import annotations

from typing import Any

from mac_audit_agent.analyzers import redact_sensitive_text
from mac_audit_agent.live_response.models import FileArtifact, NetworkArtifact, PersistenceArtifact, ProcessArtifact


def process_artifacts_from_scan(scan_result) -> list[ProcessArtifact]:
    artifacts = []
    processes = scan_result.artifacts.get("processes", {}).get("all", []) if scan_result is not None else []
    for item in processes:
        payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        artifacts.append(
            ProcessArtifact(
                pid=_safe_int(payload.get("pid")),
                name=str(payload.get("name", payload.get("process_name", payload.get("command", "")))),
                path=str(payload.get("path", payload.get("command_path", ""))),
                cmdline=redact_sensitive_text(str(payload.get("command", payload.get("cmdline", "")))),
                user=str(payload.get("user", "")),
                signature_status=str(payload.get("signature_status", payload.get("signed_status", "unknown"))),
                risk_indicator=str(payload.get("risk_indicator", payload.get("trust_level", ""))),
            )
        )
    return artifacts


def network_artifacts_from_scan(scan_result) -> list[NetworkArtifact]:
    artifacts: list[NetworkArtifact] = []
    ports = scan_result.artifacts.get("ports", {}) if scan_result is not None else {}
    for item in ports.get("active_connections", []) if isinstance(ports, dict) else []:
        payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        artifacts.append(
            NetworkArtifact(
                local_address=f"{payload.get('local_address', '')}:{payload.get('local_port', '')}".strip(":"),
                remote_address=f"{payload.get('remote_address', '')}:{payload.get('remote_port', '')}".strip(":"),
                port=str(payload.get("remote_port", payload.get("port", ""))),
                process=str(payload.get("process_name", payload.get("process", ""))),
                pid=_safe_int(payload.get("pid")),
                state=str(payload.get("state", "")),
            )
        )
    return artifacts


def network_artifacts_from_network_intelligence(payload: dict[str, Any] | None) -> list[NetworkArtifact]:
    artifacts: list[NetworkArtifact] = []
    if not isinstance(payload, dict):
        return artifacts
    for item in payload.get("connections", []):
        if not isinstance(item, dict):
            continue
        artifacts.append(
            NetworkArtifact(
                local_address=f"{item.get('local_address', '')}:{item.get('local_port', '')}".strip(":"),
                remote_address=f"{item.get('remote_address', '')}:{item.get('remote_port', '')}".strip(":"),
                port=str(item.get("remote_port", "")),
                process=str(item.get("process_name", "")),
                pid=_safe_int(item.get("pid")),
                state=str(item.get("state", "")),
            )
        )
    return artifacts


def file_artifacts_from_scan(scan_result) -> list[FileArtifact]:
    artifacts: list[FileArtifact] = []
    if scan_result is None:
        return artifacts
    for key in ("file_issues", "permission_snapshots"):
        for item in scan_result.artifacts.get(key, []):
            payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
            artifacts.append(
                FileArtifact(
                    path=str(payload.get("path", "")),
                    hash=str(payload.get("sha256", payload.get("hash", ""))),
                    permissions=str(payload.get("mode", payload.get("permissions", ""))),
                    owner=str(payload.get("owner", "")),
                    modified_time=str(payload.get("modified_at", payload.get("mtime", ""))),
                    risk_flag=str(payload.get("severity", payload.get("risk_flag", ""))),
                    source=f"msaa_{key}",
                )
            )
    return artifacts


def persistence_artifacts_from_scan(scan_result) -> list[PersistenceArtifact]:
    artifacts: list[PersistenceArtifact] = []
    if scan_result is None:
        return artifacts
    for item in scan_result.artifacts.get("launch_snapshots", []):
        payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        artifacts.append(
            PersistenceArtifact(
                mechanism="launchd",
                path=str(payload.get("path", payload.get("plist_path", ""))),
                launch_item=str(payload.get("label", payload.get("name", ""))),
                risk_score=_safe_int(payload.get("risk_score")) or 0,
                source="msaa_scan_launch_snapshots",
            )
        )
    return artifacts


def persistence_artifacts_from_report(report) -> list[PersistenceArtifact]:
    artifacts: list[PersistenceArtifact] = []
    for item in getattr(report, "items", []) or []:
        payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        artifacts.append(
            PersistenceArtifact(
                mechanism=str(payload.get("mechanism", "")),
                path=str(payload.get("path", payload.get("plist_path", ""))),
                launch_item=str(payload.get("label", payload.get("name", ""))),
                risk_score=_safe_int(payload.get("risk_score")) or 0,
                source="msaa_persistence_intelligence",
            )
        )
    return artifacts


def user_session_artifacts_from_scan(scan_result) -> list[dict[str, Any]]:
    if scan_result is None:
        return []
    users = []
    for item in scan_result.artifacts.get("users", []):
        users.append(item.to_dict() if hasattr(item, "to_dict") else dict(item))
    return users


def security_artifacts_from_scan(scan_result) -> list[dict[str, Any]]:
    if scan_result is None:
        return []
    artifacts = []
    for key in ("ssh_artifacts", "sudoers_findings", "system_integrity", "physical_devices"):
        value = scan_result.artifacts.get(key)
        if value:
            artifacts.append({"source": f"msaa_{key}", "payload": value})
    return artifacts


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None

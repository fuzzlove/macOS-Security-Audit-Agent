from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import socket
import getpass
from dataclasses import dataclass, field
from pathlib import Path

from mac_audit_agent.analyzers import parse_launchd_plist
from mac_audit_agent.models import BackgroundMonitorEvent, LaunchItemSnapshot, utc_now_iso
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_event
from mac_audit_agent.persistence_intelligence.mitre_mapping import mitre_for_mechanism


PERSISTENCE_DIRECTORIES = (
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
)

PERSISTENCE_ARTIFACT_LOCATIONS = (
    ("privileged_helper", "/Library/PrivilegedHelperTools"),
    ("kernel_extension", "/Library/Extensions"),
    ("system_extension", "/Library/SystemExtensions"),
    ("cron_job", "/private/var/at/tabs"),
    ("cron_job", "/var/at/tabs"),
    ("legacy_startup_item", "/Library/StartupItems"),
    ("background_task_management", "~/Library/Application Support/com.apple.backgroundtaskmanagementagent"),
    ("login_hook_config", "/Library/Preferences/com.apple.loginwindow.plist"),
    ("login_hook_config", "~/Library/Preferences/com.apple.loginwindow.plist"),
    ("event_rule", "/etc/emond.d/rules"),
    ("directory_services_plugin", "/Library/DirectoryServices/PlugIns"),
    ("spotlight_importer", "/Library/Spotlight"),
    ("spotlight_importer", "~/Library/Spotlight"),
    ("quicklook_plugin", "/Library/QuickLook"),
    ("quicklook_plugin", "~/Library/QuickLook"),
    ("startup_script", "/etc/rc.cleanup"),
    ("startup_script", "/etc/rc.common"),
    ("startup_script", "/etc/rc.installer_cleanup"),
    ("startup_script", "/etc/rc.server"),
    ("startup_script", "/etc/launchd.conf"),
    ("ssh_authorized_key", "~/.ssh/authorized_keys"),
    ("ssh_configuration", "~/.ssh/config"),
    ("shell_startup", "~/.zshrc"),
    ("shell_startup", "~/.zprofile"),
    ("shell_startup", "~/.bash_profile"),
    ("shell_startup", "~/.profile"),
    ("applescript_persistence", "~/Library/Scripts"),
    ("applescript_persistence", "~/Library/Services"),
    ("applescript_persistence", "~/Library/Application Scripts"),
)
MAX_ARTIFACTS_PER_LOCATION = 100
MAX_ARTIFACTS_TOTAL = 500
MAX_ARTIFACT_HASH_BYTES = 1_000_000

LOGIN_ITEM_SCRIPT = 'tell application "System Events" to get the name of every login item'


def _run_command(command: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:  # pragma: no cover - environment specific
        return 1, "", str(exc)


@dataclass
class PersistenceArtifactSnapshot:
    path: str
    mechanism: str
    fingerprint: str
    size: int = 0
    modified_ns: int = 0
    mode: str = ""
    owner_uid: int = -1
    content_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "mechanism": self.mechanism,
            "fingerprint": self.fingerprint,
            "size": self.size,
            "modified_ns": self.modified_ns,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "content_sha256": self.content_sha256,
        }


@dataclass
class PersistenceSnapshot:
    timestamp: str = field(default_factory=utc_now_iso)
    launch_items: list[LaunchItemSnapshot] = field(default_factory=list)
    login_items: list[str] = field(default_factory=list)
    artifacts: list[PersistenceArtifactSnapshot] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "launch_items": [item.to_dict() for item in self.launch_items],
            "login_items": list(self.login_items),
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


class PersistenceMonitor:
    def __init__(self, executor=_run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> PersistenceSnapshot:
        launch_items = self._collect_launch_items()
        login_items = self._collect_login_items()
        return PersistenceSnapshot(
            launch_items=sorted(launch_items, key=lambda item: item.path),
            login_items=sorted(set(login_items)),
            artifacts=self._collect_persistence_artifacts(),
        )

    def evaluate(self, previous: PersistenceSnapshot | None, current: PersistenceSnapshot) -> list[BackgroundMonitorEvent]:
        if previous is None:
            return []
        previous_launch = {item.path: item for item in previous.launch_items}
        current_launch = {item.path: item for item in current.launch_items}
        previous_login = set(previous.login_items)
        current_login = set(current.login_items)

        events: list[BackgroundMonitorEvent] = []
        new_launch_items = [item for path, item in current_launch.items() if path not in previous_launch]
        new_login_items = sorted(current_login - previous_login)
        removed_launch_items = [item for path, item in previous_launch.items() if path not in current_launch]
        modified_launch_items = [
            item for path, item in current_launch.items()
            if path in previous_launch and item.to_dict() != previous_launch[path].to_dict()
        ]
        previous_artifacts = {item.path: item for item in previous.artifacts}
        current_artifacts = {item.path: item for item in current.artifacts}
        added_artifacts = [item for path, item in current_artifacts.items() if path not in previous_artifacts]
        removed_artifacts = [item for path, item in previous_artifacts.items() if path not in current_artifacts]
        modified_artifacts = [
            item for path, item in current_artifacts.items()
            if path in previous_artifacts and item.fingerprint != previous_artifacts[path].fingerprint
        ]

        new_daemons = [item for item in new_launch_items if item.path.startswith("/Library/LaunchDaemons")]
        new_agents = [item for item in new_launch_items if "LaunchAgents" in item.path]
        if new_daemons:
            events.append(self._launch_event("launchdaemon_added", "critical", new_daemons, current.timestamp))
        if new_agents:
            events.append(self._launch_event("launchagent_added", "high", new_agents, current.timestamp))
        if new_login_items:
            events.append(self._login_event("persistence_item_created_high_risk", "critical", new_login_items, current.timestamp))
        if modified_launch_items:
            events.append(self._launch_event("persistence_item_modified", "high", modified_launch_items, current.timestamp, change="modified"))
        if removed_launch_items:
            events.append(self._launch_event("persistence_item_removed", "medium", removed_launch_items, current.timestamp, change="removed"))
        for change, artifacts in (("added", added_artifacts), ("modified", modified_artifacts), ("removed", removed_artifacts)):
            for mechanism in sorted({item.mechanism for item in artifacts}):
                matching = [item for item in artifacts if item.mechanism == mechanism]
                events.append(self._artifact_event(change, mechanism, matching, current.timestamp))
        return events

    def summarize_inventory(self, snapshot: PersistenceSnapshot) -> dict[str, object]:
        launch_items = snapshot.launch_items
        return {
            "launch_daemons": [item.to_dict() for item in launch_items if item.path.startswith("/Library/LaunchDaemons")],
            "launch_agents": [item.to_dict() for item in launch_items if "LaunchAgents" in item.path],
            "login_items": list(snapshot.login_items),
            "persistence_artifacts": [item.to_dict() for item in snapshot.artifacts],
        }

    def _collect_persistence_artifacts(self) -> list[PersistenceArtifactSnapshot]:
        artifacts: list[PersistenceArtifactSnapshot] = []
        seen: set[str] = set()
        for mechanism, raw_root in PERSISTENCE_ARTIFACT_LOCATIONS:
            if len(artifacts) >= MAX_ARTIFACTS_TOTAL:
                break
            root = Path(raw_root).expanduser()
            try:
                if root.is_dir():
                    children = sorted(root.iterdir(), key=lambda path: path.name)[:MAX_ARTIFACTS_PER_LOCATION]
                elif root.is_file():
                    children = [root]
                else:
                    children = []
            except (OSError, PermissionError):
                continue
            for path in children:
                normalized = str(path)
                if normalized in seen:
                    continue
                seen.add(normalized)
                artifact = self._artifact_snapshot(path, mechanism)
                if artifact is not None:
                    artifacts.append(artifact)
                    if len(artifacts) >= MAX_ARTIFACTS_TOTAL:
                        break
        return sorted(artifacts, key=lambda item: (item.mechanism, item.path))

    def _artifact_snapshot(self, path: Path, mechanism: str) -> PersistenceArtifactSnapshot | None:
        try:
            details = path.lstat()
            digest = hashlib.sha256()
            digest.update(f"{details.st_mode}:{details.st_uid}:{details.st_size}:{details.st_mtime_ns}".encode())
            content_sha256 = ""
            if stat.S_ISREG(details.st_mode) and details.st_size <= MAX_ARTIFACT_HASH_BYTES:
                content_digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                        content_digest.update(chunk)
                content_sha256 = content_digest.hexdigest()
            return PersistenceArtifactSnapshot(
                path=str(path), mechanism=mechanism, fingerprint=digest.hexdigest(),
                size=details.st_size, modified_ns=details.st_mtime_ns,
                mode=oct(stat.S_IMODE(details.st_mode)), owner_uid=details.st_uid,
                content_sha256=content_sha256,
            )
        except (OSError, PermissionError):
            return None

    def _collect_launch_items(self) -> list[LaunchItemSnapshot]:
        snapshots: list[LaunchItemSnapshot] = []
        for root in PERSISTENCE_DIRECTORIES:
            base = Path(root).expanduser()
            if not base.exists():
                continue
            for path in sorted(base.glob("*.plist"))[:200]:
                if not path.is_file() or not os.access(path, os.R_OK):
                    continue
                try:
                    snapshots.append(parse_launchd_plist(path.read_bytes(), str(path)))
                except Exception:
                    continue
        return snapshots

    def _collect_login_items(self) -> list[str]:
        code, stdout, _stderr = self.executor(["/usr/bin/osascript", "-e", LOGIN_ITEM_SCRIPT])
        if code != 0:
            return []
        items: list[str] = []
        for token in re.split(r"[\n,]", stdout):
            cleaned = token.strip().strip('"').strip("'")
            if cleaned:
                items.append(cleaned)
        return items

    def _launch_event(self, event_type: str, severity: str, items: list[LaunchItemSnapshot], timestamp: str, *, change: str = "added") -> BackgroundMonitorEvent:
        summary = self._summarize_launch_items(items)
        evidence = f"Persistence launch items {change}: {summary}."
        rule = rule_for_event(event_type)
        metadata = {
            "items": [item.to_dict() for item in items],
            "summary": summary,
            "category": event_type,
            "change": change,
        }
        primary_path = items[0].path if items else ""
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{self._fingerprint(summary)}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source="persistence_observer",
            evidence=evidence,
            confidence="high",
            recommendation="Review the owner, path, and purpose of the new persistence item before allowing it to remain installed.",
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="launchd_detector",
            trigger_subsource="launchdaemon_snapshot" if event_type == "launchdaemon_added" else "launchagent_snapshot",
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=summary,
            normalized_signal=normalized_signal(event_type, summary, primary_path),
            evidence_hash=evidence_hash(event_type, summary, primary_path),
            related_path=primary_path,
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state="persistence item absent" if change == "added" else f"persistence item state before {change}",
            current_state=f"persistence item present: {summary}" if change != "removed" else "persistence item absent",
            baseline_status=f"persistence {change}",
            correlation_id=correlation_id_for(event_type, summary, primary_path, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Summary={summary}",
        )

    def _artifact_event(self, change: str, mechanism: str, items: list[PersistenceArtifactSnapshot], timestamp: str) -> BackgroundMonitorEvent:
        names = [Path(item.path).name for item in items]
        summary = self._summarize_names(names)
        event_type = {
            "added": "persistence_artifact_added",
            "modified": "persistence_artifact_modified",
            "removed": "persistence_artifact_removed",
        }[change]
        severity = "high" if change != "removed" else "medium"
        if mechanism in {"privileged_helper", "kernel_extension", "system_extension"} and change != "removed":
            severity = "critical"
        if mechanism == "ssh_authorized_key" and change != "removed":
            severity = "critical"
        rule = rule_for_event(event_type)
        primary_path = items[0].path if items else ""
        cvss_score = 9.5 if severity == "critical" else 8.0 if severity == "high" else 5.0
        metadata = {
            "hostname": socket.gethostname(), "username": getpass.getuser(), "event_category": "persistence",
            "persistence_type": mechanism, "object_path": primary_path, "process_name": "unavailable_from_periodic_snapshot",
            "parent_process": "unavailable_from_periodic_snapshot", "signature_status": "not_assessed_by_snapshot_monitor",
            "developer_identity": "", "team_id": "", "sha256": items[0].content_sha256 if items else "",
            "mitre_attack_mapping": mitre_for_mechanism(mechanism), "severity": severity, "cvss_score": cvss_score,
            "description": f"Persistence artifact {change}: {summary}",
            "recommended_action": "Review owner, signature, responsible process evidence, and baseline history before remediation.",
            "analyst_status": "open", "mechanism": mechanism, "change": change,
            "items": [item.to_dict() for item in items], "summary": summary,
        }
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{self._fingerprint(mechanism + summary)}",
            timestamp=timestamp, event_type=event_type, severity=severity,
            source="persistence_observer", confidence="high",
            evidence=f"Persistence artifact {change} ({mechanism.replace('_', ' ')}): {summary}.",
            recommendation="Review the artifact owner, signature, responsible installer, and referenced executable before remediation.",
            metadata_json=json.dumps(metadata, sort_keys=True), rule_id=rule.rule_id, rule_name=rule.name,
            trigger_source="persistence_artifact_detector", trigger_subsource=mechanism,
            trigger_rule_id=rule.rule_id, trigger_rule_name=rule.name,
            raw_signal_summary=summary, normalized_signal=normalized_signal(event_type, mechanism, summary, primary_path),
            evidence_hash=evidence_hash(event_type, mechanism, summary, primary_path), related_path=primary_path,
            first_seen=timestamp, last_seen=timestamp,
            previous_state="artifact absent" if change == "added" else f"artifact present before {change}",
            current_state="artifact absent" if change == "removed" else f"artifact present: {summary}",
            baseline_status=f"persistence artifact {change}",
            correlation_id=correlation_id_for(event_type, mechanism, primary_path, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints), recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector=persistence_artifact_detector; mechanism={mechanism}; rule={rule.rule_id}; summary={summary}",
        )

    def _login_event(self, event_type: str, severity: str, items: list[str], timestamp: str) -> BackgroundMonitorEvent:
        summary = self._summarize_names(items)
        evidence = f"New login items added: {summary}."
        rule = rule_for_event(event_type)
        metadata = {
            "items": list(items),
            "summary": summary,
            "category": event_type,
        }
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{self._fingerprint(summary)}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source="persistence_observer",
            evidence=evidence,
            confidence="high",
            recommendation="Review the new login item and confirm it is expected for the current user and workstation.",
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="launchd_detector",
            trigger_subsource="login_item_snapshot",
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=summary,
            normalized_signal=normalized_signal(event_type, summary, ",".join(items)),
            evidence_hash=evidence_hash(event_type, summary, items),
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state="login item absent",
            current_state=f"login item present: {summary}",
            baseline_status="new persistence",
            correlation_id=correlation_id_for(event_type, summary, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Summary={summary}",
        )

    def _summarize_launch_items(self, items: list[LaunchItemSnapshot]) -> str:
        labels = [f"{item.label} ({Path(item.path).name})" for item in items]
        return self._summarize_names(labels)

    def _summarize_names(self, items: list[str]) -> str:
        if not items:
            return "none"
        visible = items[:4]
        summary = "; ".join(visible)
        if len(items) > len(visible):
            summary += f"; and {len(items) - len(visible)} more"
        return summary

    def _fingerprint(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

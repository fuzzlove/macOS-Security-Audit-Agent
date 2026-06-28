from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import Finding, ScanResult, utc_now_iso
from mac_audit_agent.storage import json_safe


SUSPICIOUS_EXECUTION_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/Users/Shared/",
)
MONITORING_BLINDNESS_COMPONENTS = {
    "Monitor Heartbeat",
    "System Daemon Status",
    "User Notifier Status",
    "SQLite Health",
    "Detector Freshness",
    "Alert Overlay Health",
    "Event Backlog",
    "Last Successful Event Delivery",
}


@dataclass
class SystemIntegrityReport:
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "checks_run": list(self.checks_run),
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


class SystemIntegrityEngine:
    def analyze_scan_result(self, scan_result: ScanResult) -> SystemIntegrityReport:
        artifacts = dict(scan_result.collected_artifacts)
        artifacts.setdefault("findings", [finding.to_dict() for finding in scan_result.findings])
        artifacts.setdefault("baseline_diff", scan_result.baseline_diff)
        return self.analyze_artifacts(artifacts)

    def analyze_artifacts(self, artifacts: dict[str, Any]) -> SystemIntegrityReport:
        checks_run: list[str] = []
        findings: list[Finding] = []
        for check_name, check in [
            ("hidden_process_indicators", self._hidden_process_indicators),
            ("hidden_port_indicators", self._hidden_port_indicators),
            ("persistence_consistency", self._persistence_consistency),
            ("suspicious_execution_locations", self._suspicious_execution_locations),
            ("library_injection_indicators", self._library_injection_indicators),
            ("monitoring_blindness", self._monitoring_blindness),
        ]:
            checks_run.append(check_name)
            findings.extend(check(artifacts))
        return SystemIntegrityReport(generated_at=utc_now_iso(), findings=findings, checks_run=checks_run)

    def _hidden_process_indicators(self, artifacts: dict[str, Any]) -> list[Finding]:
        views: dict[str, set[str]] = {}
        processes = artifacts.get("processes", {})
        if isinstance(processes, dict):
            self._add_process_view(views, "processes.all", processes.get("all", []))
            for key in ("ps", "ps_output", "netstat_processes", "lsof_processes", "process_views"):
                if key in processes:
                    self._add_process_view(views, f"processes.{key}", processes.get(key))
        for key in ("ps_processes", "process_snapshots", "process_views"):
            if key in artifacts:
                self._add_process_view(views, key, artifacts.get(key))
        populated = {name: values for name, values in views.items() if values}
        if len(populated) < 2:
            return []
        all_items = set().union(*populated.values())
        mismatches: list[str] = []
        for item in sorted(all_items):
            present = [name for name, values in populated.items() if item in values]
            if len(present) != len(populated):
                missing = sorted(set(populated) - set(present))
                mismatches.append(f"{item} present_in={','.join(present)} missing_from={','.join(missing)}")
        if not mismatches:
            return []
        return [
            self._finding(
                finding_id="system_integrity_hidden_process_visibility_mismatch",
                title="Process visibility mismatch",
                severity="medium",
                description="Different process views did not agree on the same observed process set.",
                evidence="; ".join(mismatches[:10]),
                confidence="medium",
                false_positive_notes="Short-lived processes, sampling delay, permission limits, and command truncation can explain process view differences.",
                recommended_next_steps="Re-run process enumeration close together in time, preserve raw command output, and compare PID, executable path, parent PID, and user.",
                tags=["visibility mismatch", "stealth indicator", "review recommended"],
            )
        ]

    def _hidden_port_indicators(self, artifacts: dict[str, Any]) -> list[Finding]:
        localhost_scan = artifacts.get("localhost_scan", {})
        nmap = localhost_scan.get("nmap", {}) if isinstance(localhost_scan, dict) else {}
        nmap_ports = nmap.get("ports", []) if isinstance(nmap, dict) else []
        ports = artifacts.get("ports", {})
        listening = ports.get("listening", []) if isinstance(ports, dict) else []
        owned = {self._port_key(item) for item in listening if self._port_key(item)}
        mismatches: list[dict[str, Any]] = []
        for item in nmap_ports:
            if not isinstance(item, dict):
                continue
            state = str(item.get("state", "")).lower()
            if state != "open":
                continue
            key = self._port_key(item)
            if key and key not in owned:
                mismatches.append(item)
        if not mismatches:
            return []
        evidence = "; ".join(f"{item.get('protocol', '')}/{item.get('port', '')} state={item.get('state', '')} service={item.get('service', '')}" for item in mismatches[:10])
        return [
            self._finding(
                finding_id="system_integrity_hidden_port_visibility_mismatch",
                title="Port ownership visibility mismatch",
                severity="high" if any(str(item.get("protocol", "")).lower() == "tcp" for item in mismatches) else "medium",
                description="Nmap observed an open localhost port that local ownership enumeration did not identify.",
                evidence=evidence,
                confidence="medium",
                false_positive_notes="Race conditions, permission limits, UDP ambiguity, sandboxing, or a service exiting between scans can produce this mismatch.",
                recommended_next_steps="Re-run Nmap and lsof/netstat immediately, capture timestamps, identify the owning process, and review whether the listener is expected.",
                tags=["visibility mismatch", "stealth indicator", "review recommended"],
            )
        ]

    def _persistence_consistency(self, artifacts: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        baseline = artifacts.get("baseline_drift", {})
        drift_items = baseline.get("findings", []) if isinstance(baseline, dict) else []
        persistence_items = [
            item
            for item in drift_items
            if isinstance(item, dict) and str(item.get("category", "")) in {"launchagents", "launchdaemons", "login_items", "profiles_mdm"}
        ]
        if persistence_items:
            findings.append(
                self._finding(
                    finding_id="system_integrity_persistence_baseline_consistency",
                    title="Persistence baseline consistency review",
                    severity="medium",
                    description="Persistence-related entries changed compared with the trusted baseline.",
                    evidence="; ".join(f"{item.get('category')}:{item.get('change_type')}:{item.get('item_key')}" for item in persistence_items[:10]),
                    confidence="medium",
                    false_positive_notes="Software updates, MDM changes, security tools, backup agents, and user-approved login items can legitimately change persistence entries.",
                    recommended_next_steps="Verify plist owner, mode, target executable, code signature, package receipt, and whether the change was expected.",
                    tags=["system integrity anomaly", "review recommended"],
                )
            )
        suspicious_launch = []
        for item in artifacts.get("launch_snapshots", []):
            payload = self._as_dict(item)
            if payload.get("suspicious") or payload.get("signed_status") == "unsigned" or payload.get("mode") in {"777", "666"}:
                suspicious_launch.append(payload)
        if suspicious_launch:
            findings.append(
                self._finding(
                    finding_id="system_integrity_persistence_metadata_review",
                    title="Persistence metadata review",
                    severity="medium",
                    description="Persistence entries have ownership, mode, target, or signature attributes that need verification.",
                    evidence="; ".join(str(item.get("path") or item.get("label") or item.get("program")) for item in suspicious_launch[:10]),
                    confidence="medium",
                    false_positive_notes="Developer agents and internal management tooling may use nonstandard paths or unsigned local helpers.",
                    recommended_next_steps="Inspect owner, file mode, target executable, code signature, quarantine metadata, and package or MDM origin.",
                    tags=["system integrity anomaly", "review recommended"],
                )
            )
        return findings

    def _suspicious_execution_locations(self, artifacts: dict[str, Any]) -> list[Finding]:
        candidates: list[dict[str, Any]] = []
        processes = artifacts.get("processes", {})
        if isinstance(processes, dict):
            candidates.extend(self._as_dict(item) for item in processes.get("all", []))
        candidates.extend(self._as_dict(item) for item in artifacts.get("process_snapshots", []))
        candidates.extend(self._as_dict(item) for item in artifacts.get("file_issues", []))
        flagged = []
        for item in candidates:
            path = str(item.get("command_path") or item.get("path") or "")
            if not path:
                continue
            signed_status = str(item.get("signed_status", "unknown")).lower()
            reasons = set(str(reason) for reason in item.get("reasons", []))
            suspicious_path = path.startswith(SUSPICIOUS_EXECUTION_PREFIXES) or self._contains_hidden_directory(path)
            unsigned = signed_status == "unsigned"
            if suspicious_path and (unsigned or "suspicious_execution_path" in reasons or item.get("executable")):
                flagged.append(item)
        if not flagged:
            return []
        evidence = "; ".join(
            f"path={item.get('command_path') or item.get('path')} signed={item.get('signed_status', 'unknown')} pid={item.get('pid', '')}"
            for item in flagged[:10]
        )
        return [
            self._finding(
                finding_id="system_integrity_suspicious_execution_location",
                title="Suspicious execution location",
                severity="high" if any(str(item.get("signed_status", "")).lower() == "unsigned" for item in flagged) else "medium",
                description="Executable code was observed in a writable, shared, temporary, or hidden location.",
                evidence=evidence,
                confidence="medium",
                false_positive_notes="Developer builds, installers, update helpers, and temporary test tools may execute from these locations during legitimate activity.",
                recommended_next_steps="Preserve the file, verify code signature and hash, identify parent process and launch source, and confirm whether the location is expected.",
                tags=["stealth indicator", "system integrity anomaly", "review recommended"],
            )
        ]

    def _library_injection_indicators(self, artifacts: dict[str, Any]) -> list[Finding]:
        indicators: list[str] = []
        env_sources = []
        for key in ("environment_variables", "process_environment", "dyld_variables"):
            value = artifacts.get(key)
            if isinstance(value, dict):
                env_sources.extend(f"{name}={val}" for name, val in value.items())
            elif isinstance(value, list):
                env_sources.extend(str(item) for item in value)
        indicators.extend(item for item in env_sources if "DYLD_" in item)
        for item in artifacts.get("loaded_libraries", []):
            payload = self._as_dict(item)
            path = str(payload.get("path") or payload.get("library_path") or "")
            signed_status = str(payload.get("signed_status", "")).lower()
            if path and (signed_status == "unsigned" or path.startswith(SUSPICIOUS_EXECUTION_PREFIXES) or self._contains_hidden_directory(path)):
                indicators.append(f"{path} signed={signed_status or 'unknown'}")
        if not indicators:
            return []
        return [
            self._finding(
                finding_id="system_integrity_library_injection_indicator",
                title="Library or environment injection indicator",
                severity="medium",
                description="Observable dynamic loader variables or library metadata require review.",
                evidence="; ".join(indicators[:10]),
                confidence="low",
                false_positive_notes="Debugging, development tooling, profiling, and compatibility wrappers can intentionally use DYLD variables or unsigned local libraries.",
                recommended_next_steps="Confirm the parent process, environment source, loaded library path, code signature, and whether a developer or management tool set the variable.",
                tags=["stealth indicator", "system integrity anomaly", "review recommended"],
            )
        ]

    def _monitoring_blindness(self, artifacts: dict[str, Any]) -> list[Finding]:
        visibility = artifacts.get("visibility_integrity", {})
        components = visibility.get("components", []) if isinstance(visibility, dict) else []
        failing = []
        for item in components:
            if not isinstance(item, dict):
                continue
            name = str(item.get("component_name", ""))
            status = str(item.get("status", "")).lower()
            if name in MONITORING_BLINDNESS_COMPONENTS and status in {"degraded", "failing", "disabled"}:
                failing.append(item)
        if not failing:
            return []
        severity = "high" if any(str(item.get("status", "")).lower() == "failing" for item in failing) else "medium"
        return [
            self._finding(
                finding_id="system_integrity_monitoring_blindness",
                title="Monitoring blindness indicator",
                severity=severity,
                description="One or more monitoring visibility components are degraded, failing, or disabled.",
                evidence="; ".join(f"{item.get('component_name')} status={item.get('status')} evidence={item.get('evidence', '')}" for item in failing[:10]),
                confidence="high",
                false_positive_notes="Monitoring may be intentionally paused during maintenance, upgrades, privacy-sensitive work, or first-run setup.",
                recommended_next_steps="Repair the affected monitor component, confirm heartbeat and detector freshness, verify notifier delivery, and preserve the visibility report.",
                tags=["visibility mismatch", "system integrity anomaly", "review recommended"],
            )
        ]

    def _finding(
        self,
        *,
        finding_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: str,
        confidence: str,
        false_positive_notes: str,
        recommended_next_steps: str,
        tags: list[str],
    ) -> Finding:
        return Finding(
            id=finding_id,
            category="System Integrity",
            title=title,
            severity=severity,  # type: ignore[arg-type]
            description=description,
            evidence=evidence,
            command_used="system integrity correlation",
            remediation_suggestion=recommended_next_steps,
            warning="Evidence-based anomaly only; review recommended before taking action.",
            confidence=confidence,  # type: ignore[arg-type]
            evidence_summary=evidence[:500],
            raw_evidence_ref=f"system_integrity:{finding_id}",
            why_this_matters="Visibility mismatches and unusual execution or monitoring states can reduce confidence in local audit results.",
            false_positive_notes=false_positive_notes,
            recommended_next_steps=recommended_next_steps,
            what_can_go_wrong="Acting on an anomaly without validating timestamps, process ownership, and expected maintenance activity can disrupt legitimate software.",
            verification_steps=[recommended_next_steps],
            false_positive_hints=[false_positive_notes],
            recommended_verification_steps=[recommended_next_steps],
            source_trace="system_integrity_engine",
            trigger_source="system_integrity",
            normalized_signal=", ".join(tags),
        )

    def _add_process_view(self, views: dict[str, set[str]], name: str, values: Any) -> None:
        normalized = set()
        if isinstance(values, dict):
            for key, value in values.items():
                payload = self._as_dict(value)
                normalized.add(self._process_key(payload) or str(key))
        elif isinstance(values, (list, tuple, set)):
            for item in values:
                payload = self._as_dict(item)
                key = self._process_key(payload) or (str(item) if item else "")
                if key:
                    normalized.add(key)
        views[name] = {item for item in normalized if item}

    def _process_key(self, payload: dict[str, Any]) -> str:
        pid = payload.get("pid")
        path = payload.get("command_path") or payload.get("path") or payload.get("comm") or payload.get("process_name")
        if pid in (None, "") and not path:
            return ""
        return f"{pid}:{path}"

    def _port_key(self, payload: Any) -> str:
        item = self._as_dict(payload)
        port = item.get("port")
        protocol = str(item.get("protocol", "tcp")).lower()
        if port in (None, ""):
            local_address = str(item.get("local_address", ""))
            if ":" in local_address:
                port = local_address.rsplit(":", 1)[-1]
        if port in (None, ""):
            return ""
        return f"{protocol}:{port}"

    def _contains_hidden_directory(self, path: str) -> bool:
        try:
            parts = Path(path).parts
        except Exception:
            return False
        return any(part.startswith(".") and len(part) > 1 for part in parts[:-1])

    def _as_dict(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return asdict(value) if hasattr(value, "__dataclass_fields__") else dict(value.__dict__)
        return {"value": json_safe(value)}

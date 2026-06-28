from __future__ import annotations

import grp
import hashlib
import os
import platform
import pwd
import socket
import stat
import time
import getpass
from pathlib import Path
from uuid import uuid4

from mac_audit_agent.analyzers import (
    build_process_snapshot_from_row,
    build_port_snapshot,
    compare_snapshots,
    detect_process_trust,
    detect_sudoers_risk,
    detect_suspicious_file,
    detect_suspicious_writable_executable,
    detect_weak_permission,
    extract_history_indicators,
    parse_lsof_udp_output,
    parse_launchd_plist,
    parse_lsof_listening_output,
    parse_netstat_tcp_output,
    parse_ps_axo_output,
    parse_ps_output,
    parse_sudoers,
    redact_sensitive_text,
    safe_int,
    summarize_authorized_keys,
)
from mac_audit_agent.command_registry import build_command_registry
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.intrusion_methods import (
    analyze_launch_item_for_persistence,
    analyze_vmmap_output,
    scan_persistence_methods,
)
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_finding
from mac_audit_agent.models import (
    AuditCommand,
    BaselineComparison,
    CollectorResult,
    FileIssueSnapshot,
    Finding,
    HistoryIndicator,
    LaunchItemSnapshot,
    PermissionSnapshot,
    PortSnapshot,
    ProcessSnapshot,
    RawLogEntry,
    ScanError,
    ScanResult,
    UserSnapshot,
    get_exit_code,
    get_stderr,
    get_stdout,
    utc_now_iso,
)
from mac_audit_agent.network_discovery import discover_local_network
from mac_audit_agent.nmap_wrapper import (
    DEFAULT_SCAN_PROFILE,
    NMAP_INSTALL_MESSAGE,
    NmapScanResult,
    find_nmap_binary,
    profile_for_scan,
    run_nmap_scan,
)
from mac_audit_agent.runner import SafeCommandRunner
from mac_audit_agent.system_integrity import SystemIntegrityEngine


SEVERITY_WEIGHTS = {"info": 0, "low": 2, "medium": 7, "high": 15, "critical": 25}
LOCALHOST_SCAN_TARGET = "127.0.0.1"
LOCALHOST_SAFE_PORTS = [22, 80, 443, 445, 5900, 8000, 8080, 8443, 9000, 9001, 9200, 27017]
TARGET_DIRECTORIES = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/Library/PrivilegedHelperTools",
    "/tmp",
    "/var/tmp",
    "/private/tmp",
    "/Users/Shared",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications",
]


class CollectorSuite:
    def __init__(self, runner: SafeCommandRunner, config: AuditConfig | None = None) -> None:
        self.runner = runner
        self.config = config or AuditConfig(dry_run=runner.config.dry_run)
        self.registry = build_command_registry()

    def run_safe_scan(
        self,
        previous_result: ScanResult | None = None,
        *,
        scan_mode: str = "safe",
        localhost_scan_protocol: str = "tcp",
        localhost_scan_target: str | None = None,
    ) -> ScanResult:
        return self.run_scan(
            previous_result=previous_result,
            scan_mode=scan_mode,
            localhost_scan_protocol=localhost_scan_protocol,
            localhost_scan_target=localhost_scan_target,
        )

    def run_scan(
        self,
        previous_result: ScanResult | None = None,
        *,
        scan_mode: str = "safe",
        localhost_scan_protocol: str = "tcp",
        localhost_scan_target: str | None = None,
    ) -> ScanResult:
        scan_result = ScanResult(
            scan_id=str(uuid4()),
            timestamp=utc_now_iso(),
            hostname=socket.gethostname(),
            current_user=getpass.getuser(),
        )
        previous_artifacts = previous_result.collected_artifacts if previous_result else {}
        registry_result = self._run_collector(
            "command_registry",
            "registry",
            {"command_results": []},
            lambda: {"command_results": self._run_registry_commands()},
        )
        command_results = list(registry_result.artifacts["command_results"])

        system_info_result = self._run_collector(
            "system_info",
            "local system inspection",
            {"system_info": {}},
            lambda: {"system_info": self._collect_system_info(command_results)},
        )
        ports_result = self._run_collector(
            "ports",
            "network.listening_ports",
            {"ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}},
            lambda: self._collect_ports_result(command_results),
        )
        localhost_scan_result = self._run_collector(
            "localhost_port_scan",
            "127.0.0.1 localhost scan",
            {"localhost_scan": self._empty_localhost_scan_artifact(scan_mode, localhost_scan_protocol)},
            lambda: {"localhost_scan": self._collect_localhost_port_scan(scan_mode, localhost_scan_protocol, localhost_scan_target)},
        )
        users_result = self._run_collector(
            "users",
            "pwd/grp + dscl/defaults",
            {"users": []},
            lambda: {"users": self._collect_users(command_results)},
        )
        users = users_result.artifacts["users"]
        history_result = self._run_collector(
            "history",
            "shell history files",
            {"history_indicators": []},
            lambda: {"history_indicators": self._collect_history_indicators(users)},
        )
        permissions_result = self._run_collector(
            "permissions",
            "stat metadata",
            {"permission_snapshots": []},
            lambda: {"permission_snapshots": self._collect_permission_snapshots(users)},
        )
        processes_result = self._run_collector(
            "processes",
            "files.running_processes",
            {"processes": {"all": [], "suspicious": [], "errors": []}, "command_results": []},
            lambda: self._collect_processes_result(command_results),
        )
        command_results.extend(processes_result.artifacts.get("command_results", []))
        launch_items_result = self._run_collector(
            "launch_items",
            "launchd plist files",
            {"launch_snapshots": []},
            lambda: {"launch_snapshots": self._collect_launch_items()},
        )
        intrusion_methods_result = self._run_collector(
            "intrusion_methods",
            "ATT&CK persistence and memory heuristics",
            {"intrusion_methods": {"persistence": [], "memory": [], "errors": []}, "command_results": []},
            lambda: self._collect_intrusion_methods_result(processes_result.artifacts["processes"]["all"], launch_items_result.artifacts["launch_snapshots"]),
        )
        command_results.extend(intrusion_methods_result.artifacts.get("command_results", []))
        files_result = self._run_collector(
            "files",
            "targeted filesystem walk",
            {"file_issues": [], "launch_items": [], "command_results": []},
            lambda: self._collect_file_issues_result(),
        )
        command_results.extend(files_result.artifacts.get("command_results", []))
        sudoers_result = self._run_collector(
            "sudoers",
            "readable sudoers files",
            {"sudoers_findings": []},
            lambda: {"sudoers_findings": self._collect_sudoers_findings(users)},
        )
        network_info_result = self._run_collector(
            "network_services",
            "network and sharing commands",
            {"network_info": {}},
            lambda: {"network_info": self._collect_network_info(command_results)},
        )
        ssh_result = self._run_collector(
            "ssh",
            "ssh metadata",
            {"ssh_artifacts": {}},
            lambda: {"ssh_artifacts": self._collect_ssh_artifacts(users)},
        )

        system_info = system_info_result.artifacts["system_info"]
        ports_artifact = ports_result.artifacts["ports"]
        localhost_scan_artifact = localhost_scan_result.artifacts["localhost_scan"]
        ports = ports_artifact["listening"]
        history_indicators = history_result.artifacts["history_indicators"]
        permission_snapshots = permissions_result.artifacts["permission_snapshots"]
        processes = processes_result.artifacts["processes"]
        process_snapshots = processes["all"]
        launch_snapshots = launch_items_result.artifacts["launch_snapshots"]
        file_issues = files_result.artifacts["file_issues"]
        launch_items = set(files_result.artifacts.get("launch_items", []))
        network_info = network_info_result.artifacts["network_info"]
        ssh_artifacts = ssh_result.artifacts["ssh_artifacts"]

        findings: list[Finding] = []
        collector_results = [
            registry_result,
            system_info_result,
            ports_result,
            localhost_scan_result,
            users_result,
            history_result,
            permissions_result,
            processes_result,
            launch_items_result,
            files_result,
            sudoers_result,
            network_info_result,
            ssh_result,
        ]
        for collector_result in collector_results:
            scan_result.raw_logs.extend(collector_result.raw_logs)
            scan_result.errors.extend(collector_result.errors)
            findings.extend(collector_result.findings)

        findings.extend(self._findings_for_system_info(system_info))
        findings.extend(self._findings_for_ports(ports))
        findings.extend(self._findings_for_localhost_scan(ports_artifact, localhost_scan_artifact))
        findings.extend(self._findings_for_users(users))
        findings.extend(self._findings_for_history(history_indicators))
        findings.extend(self._findings_for_permissions(permission_snapshots))
        findings.extend(self._findings_for_processes(process_snapshots))
        findings.extend(self._findings_for_launch_items(launch_snapshots))
        findings.extend(self._findings_for_intrusion_methods(intrusion_methods_result.artifacts["intrusion_methods"]))
        findings.extend(self._findings_for_files(file_issues))
        findings.extend(self._findings_for_security_commands(command_results))
        findings.extend(self._findings_for_network_info(network_info))
        findings.extend(self._findings_for_ssh(ssh_artifacts))
        findings.extend(sudoers_result.artifacts["sudoers_findings"])

        previous_findings = previous_result.findings if previous_result else []
        previous_ports = self._ports_from_artifacts(previous_artifacts)
        previous_processes = self._processes_from_artifacts(previous_artifacts)
        comparison = compare_snapshots(
            previous_ports=previous_ports,
            current_ports=ports,
            previous_users=previous_artifacts.get("users", []),
            current_users=users,
            previous_permissions=previous_artifacts.get("permission_snapshots", []),
            current_permissions=permission_snapshots,
            previous_history=previous_artifacts.get("history_indicators", []),
            current_history=history_indicators,
            previous_files=previous_artifacts.get("file_issues", []),
            current_files=file_issues,
            previous_launch_items=set(previous_artifacts.get("launch_items", [])),
            current_launch_items=launch_items,
            previous_processes=previous_processes,
            current_processes=process_snapshots,
            previous_launch_snapshots=previous_artifacts.get("launch_snapshots", []),
            current_launch_snapshots=launch_snapshots,
            previous_findings=previous_findings,
            current_findings=findings,
        )
        findings.extend(self._findings_for_comparison(comparison))
        system_integrity_artifacts = {
            "system_info": system_info,
            "ports": ports_artifact,
            "localhost_scan": localhost_scan_artifact,
            "users": users,
            "permission_snapshots": permission_snapshots,
            "file_issues": file_issues,
            "processes": processes,
            "launch_snapshots": launch_snapshots,
            "network_info": network_info,
            "ssh_artifacts": ssh_artifacts,
            "baseline_diff": comparison.to_dict(),
        }
        system_integrity_report = SystemIntegrityEngine().analyze_artifacts(system_integrity_artifacts)
        findings.extend(system_integrity_report.findings)
        if not findings:
            findings.append(self._finding(
                category="Summary",
                title="Scan Completed",
                severity="info",
                description="Read-only audit completed without high-confidence findings from the enabled collectors.",
                evidence=f"host={scan_result.hostname} user={scan_result.current_user}",
                evidence_summary="Scan completed with no flagged findings from current collectors.",
                raw_evidence_ref=f"scan:{scan_result.scan_id}",
                why_this_matters="A completed baseline still provides useful host inventory and comparison data for later scans.",
                false_positive_notes="Absence of findings is not proof of absence of risk.",
                recommended_next_steps="Review the collected artifacts and rerun after system changes to establish a useful baseline.",
                what_can_go_wrong="Assuming a clean scan means the system is risk-free can create blind spots.",
                command_used="scan pipeline",
            ))

        scan_result.findings = findings
        scan_result.collected_artifacts = {
            "system_info": system_info,
            "ports": ports_artifact,
            "localhost_scan": localhost_scan_artifact,
            "users": users,
            "history_indicators": history_indicators,
            "permission_snapshots": permission_snapshots,
            "file_issues": file_issues,
            "processes": processes,
            "launch_snapshots": launch_snapshots,
            "intrusion_methods": intrusion_methods_result.artifacts["intrusion_methods"],
            "launch_items": sorted(launch_items),
            "command_results": command_results,
            "network_info": network_info,
            "ssh_artifacts": ssh_artifacts,
            "system_integrity": system_integrity_report.to_dict(),
        }
        scan_result.baseline_diff = comparison.to_dict()
        return scan_result

    def collect_network_discovery(
        self,
        *,
        interface: str,
        scan_profile: str = "standard",
        confirm_public_network: bool = False,
        progress_callback=None,
        cancel_check=None,
        previous_hosts=None,
        previous_gateway: str = "",
        previous_gateway_mac: str = "",
        previous_subnet: str = "",
    ):
        return discover_local_network(
            interface=interface,
            scan_profile=scan_profile,
            confirm_public_network=confirm_public_network,
            progress_callback=progress_callback,
            cancel_check=cancel_check,
            previous_hosts=previous_hosts,
            previous_gateway=previous_gateway,
            previous_gateway_mac=previous_gateway_mac,
            previous_subnet=previous_subnet,
        )

    def run_safe_collectors(self, previous_snapshots: dict | None = None) -> dict:
        previous_result = None
        if previous_snapshots:
            previous_result = ScanResult(
                scan_id="previous",
                timestamp=utc_now_iso(),
                hostname="",
                current_user="",
                findings=[],
                collected_artifacts=previous_snapshots,
            )
        scan_result = self.run_safe_scan(previous_result)
        artifacts = scan_result.collected_artifacts
        comparison = BaselineComparison(**scan_result.baseline_diff) if scan_result.baseline_diff else BaselineComparison()
        return {
            "command_results": artifacts.get("command_results", []),
            "findings": scan_result.findings,
            "ports": artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}),
            "localhost_scan": artifacts.get("localhost_scan", self._empty_localhost_scan_artifact("safe", "tcp")),
            "users": artifacts.get("users", []),
            "history_indicators": artifacts.get("history_indicators", []),
            "permission_snapshots": artifacts.get("permission_snapshots", []),
            "file_issues": artifacts.get("file_issues", []),
            "processes": artifacts.get("processes", {"all": [], "suspicious": [], "errors": []}),
            "launch_snapshots": artifacts.get("launch_snapshots", []),
            "launch_items": set(artifacts.get("launch_items", [])),
            "comparison": comparison,
            "dashboard": self._dashboard_summary(scan_result),
            "privacy_warnings": [
                "Shell history scanning reviews only suspicious indicators and counts by default.",
                "Shell history may still contain sensitive commands, hostnames, or secrets even when snippets are redacted.",
            ],
            "raw_logs": scan_result.raw_logs,
            "errors": scan_result.errors,
            "scan_result": scan_result,
        }

    def compute_security_score(self, findings: list[Finding] | None) -> int | None:
        if findings is None:
            return None
        if not findings:
            return 100
        penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        return max(0, min(100, 100 - penalty))

    def score_label(self, score: int | None) -> str:
        if score is None:
            return "Unavailable"
        if score >= 90:
            return "Good"
        if score >= 70:
            return "Needs Review"
        if score >= 40:
            return "Concerning"
        return "High Risk"

    def _run_registry_commands(self) -> list:
        skipped_ids = {"network.listening_ports", "files.running_processes"}
        return [
            self.runner.execute(command)
            for command in self.registry.values()
            if command.id not in skipped_ids and command.risk_level != "dangerous" and not command.mutates_system
        ]

    def _run_collector(self, collector_name: str, command_source: str, default_artifacts: dict, func) -> CollectorResult:
        result = CollectorResult(collector_name=collector_name, artifacts=dict(default_artifacts))
        try:
            value = func()
            if isinstance(value, CollectorResult):
                result.artifacts.update(value.artifacts)
                result.findings.extend(value.findings)
                result.errors.extend(value.errors)
                result.raw_logs.extend(value.raw_logs)
            elif isinstance(value, dict):
                result.artifacts.update(value)
            else:
                raise TypeError(f"{collector_name} returned unsupported collector value: {type(value)!r}")
            if "command_results" in result.artifacts:
                result.raw_logs.extend(self._command_logs(collector_name, result.artifacts["command_results"]))
            result.raw_logs.append(
                RawLogEntry(
                    collector_name=collector_name,
                    command_or_source=command_source,
                    timestamp=utc_now_iso(),
                    exit_code=0,
                    stderr_summary="",
                    stdout_summary=f"{collector_name} completed",
                )
            )
        except Exception as exc:
            error = ScanError(collector_name=collector_name, message=str(exc))
            result.errors.append(error)
            result.findings.append(self._error_finding(collector_name, str(exc)))
            result.raw_logs.append(
                RawLogEntry(
                    collector_name=collector_name,
                    command_or_source=command_source,
                    timestamp=utc_now_iso(),
                    exit_code=1,
                    stderr_summary=str(exc),
                    stdout_summary="",
                )
            )
        return result

    def _command_logs(self, collector_name: str, command_results: list) -> list[RawLogEntry]:
        logs: list[RawLogEntry] = []
        for item in command_results:
            command_id = self._result_command_id(item)
            if command_id:
                stdout_summary = get_stdout(item)[:500]
                stderr_summary = get_stderr(item)[:300]
                if self._result_dry_run(item):
                    stdout_summary = "Command skipped (dry-run mode)"
                    stderr_summary = ""
                logs.append(
                    RawLogEntry(
                        collector_name=collector_name,
                        command_or_source=self._result_command_preview(item),
                        timestamp=self._result_executed_at(item),
                        exit_code=get_exit_code(item),
                        stderr_summary=stderr_summary,
                        stdout_summary=stdout_summary,
                    )
                )
        return logs

    def _error_finding(self, collector_name: str, message: str) -> Finding:
        return self._finding(
            category="Errors",
            title=f"Collector Failed: {collector_name}",
            severity="low",
            description="A collector failed but the scan continued.",
            evidence=message,
            evidence_summary=f"{collector_name} failed",
            raw_evidence_ref=f"collector_error:{collector_name}",
            why_this_matters="Partial collection reduces coverage for that category.",
            false_positive_notes="This may be caused by missing permissions, absent files, or platform differences.",
            recommended_next_steps="Review the error, rerun the scan, and only elevate permissions manually if you explicitly choose to do so.",
            what_can_go_wrong="Ignoring repeated collector failures can leave blind spots in future audits.",
            command_used=collector_name,
        )

    def _dashboard_summary(self, scan_result: ScanResult) -> dict[str, int]:
        baseline = scan_result.baseline_diff or {}
        ports_artifact = scan_result.collected_artifacts.get("ports", {"suspicious_review_needed": []})
        return {
            "suspicious_ports": len(ports_artifact.get("suspicious_review_needed", [])),
            "users_admin_changes": len(baseline.get("new_users", [])) + len(baseline.get("new_admin_users", [])),
            "history_indicators": len(scan_result.collected_artifacts.get("history_indicators", [])),
            "suspicious_directories": len(scan_result.collected_artifacts.get("file_issues", [])) + len(scan_result.collected_artifacts.get("permission_snapshots", [])),
            "new_since_last_scan": sum(len(v) for v in baseline.values() if isinstance(v, list)),
        }

    def _ports_from_artifacts(self, artifacts: dict) -> list[PortSnapshot]:
        ports = artifacts.get("ports", [])
        if isinstance(ports, dict):
            return list(ports.get("listening", []))
        if isinstance(ports, list):
            return list(ports)
        return []

    def _processes_from_artifacts(self, artifacts: dict) -> list[ProcessSnapshot]:
        processes = artifacts.get("processes", [])
        if isinstance(processes, dict):
            return list(processes.get("all", []))
        legacy = artifacts.get("process_snapshots", [])
        if isinstance(legacy, list):
            return list(legacy)
        return []

    def _debug_stdout_preview(self, stdout: str) -> str:
        lines = stdout.splitlines()[:10]
        if not lines:
            return ""
        return "\n".join(redact_sensitive_text(line, self.config) for line in lines)

    def _result_command_id(self, result) -> str:
        if isinstance(result, dict):
            return str(result.get("command_id", ""))
        return str(getattr(result, "command_id", ""))

    def _result_command_preview(self, result) -> str:
        if isinstance(result, dict):
            return str(result.get("command_preview", result.get("preview", "")))
        return str(getattr(result, "command_preview", getattr(result, "preview", "")))

    def _result_executed_at(self, result) -> str:
        if isinstance(result, dict):
            return str(result.get("executed_at", ""))
        return str(getattr(result, "executed_at", ""))

    def _result_dry_run(self, result) -> bool:
        if isinstance(result, dict):
            return bool(result.get("dry_run", False))
        return bool(getattr(result, "dry_run", False))

    def _runtime_command(self, command_id: str, name: str, argv: list[str], category: str, timeout_seconds: int = 10) -> AuditCommand:
        return AuditCommand(
            id=command_id,
            name=name,
            description=name,
            command=argv,
            privilege_required=False,
            risk_level="safe",
            mutates_system=False,
            timeout_seconds=timeout_seconds,
            collection_warning="Read-only local collection.",
            failure_modes=["Command unavailable.", "Permission denied.", "Output parsing failed."],
            user_disclaimer="Read-only local inspection.",
            safer_alternative="Run the command manually in Terminal.",
            category=category,
        )

    def _empty_localhost_scan_artifact(self, scan_mode: str, protocol: str) -> dict[str, object]:
        return {
            "target": LOCALHOST_SCAN_TARGET,
            "mode": scan_mode,
            "protocol": protocol,
            "open_ports": [],
            "missing_from_enumeration": [],
            "errors": [],
            "scanned_port_count": 0,
            "engine": "internal_socket",
            "nmap": {
                "installed": bool(find_nmap_binary()),
                "path": find_nmap_binary() or "",
                "profile": DEFAULT_SCAN_PROFILE,
                "ports": [],
                "warnings": [],
                "errors": [],
                "fallback_used": True,
            },
        }

    def _empty_localhost_full_port_scan_artifact(self) -> dict[str, object]:
        return {
            "target": LOCALHOST_SCAN_TARGET,
            "tcp_open_ports": [],
            "tcp_banners": {},
            "udp_responsive_or_unknown_ports": [],
            "scanned_tcp_count": 0,
            "scanned_udp_count": 0,
            "errors": [],
            "engine": "internal_socket",
            "nmap": {
                "installed": bool(find_nmap_binary()),
                "path": find_nmap_binary() or "",
                "profiles": [],
                "ports": [],
                "warnings": [],
                "errors": [],
                "fallback_used": True,
            },
        }

    def _resolve_localhost_scan_target(self, override: str | None = None) -> str:
        if override not in (None, "", LOCALHOST_SCAN_TARGET):
            raise ValueError("Localhost port scan target override rejected; target is fixed to 127.0.0.1.")
        return LOCALHOST_SCAN_TARGET

    def _localhost_scan_ports_for_mode(self, scan_mode: str) -> list[int]:
        normalized_mode = str(scan_mode).strip().lower()
        if normalized_mode == "aggressive":
            return list(range(1, 65536))
        if normalized_mode == "verbose":
            return sorted(self.config.concerning_ports.keys())
        return list(LOCALHOST_SAFE_PORTS)

    def _scan_localhost_port_tcp(self, target: str, port: int, timeout: float = 0.2) -> bool:
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _scan_localhost_port_udp(self, target: str, port: int, timeout: float = 0.2) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.send(b"")
            try:
                sock.recv(1)
            except TimeoutError:
                return True
            except ConnectionRefusedError:
                return False
            except OSError:
                return False
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _grab_localhost_tcp_banner(self, target: str, port: int, timeout: float = 0.1) -> str:
        try:
            with socket.create_connection((target, port), timeout=timeout) as connection:
                connection.settimeout(timeout)
                banner = connection.recv(256)
        except OSError:
            return ""
        if not banner:
            return ""
        return banner.decode("utf-8", errors="replace").strip()

    def _collect_localhost_port_scan(
        self,
        scan_mode: str,
        protocol: str,
        target_override: str | None = None,
    ) -> dict[str, object]:
        target = self._resolve_localhost_scan_target(target_override)
        normalized_protocol = str(protocol).strip().lower()
        if normalized_protocol not in {"tcp", "udp", "both"}:
            raise ValueError(f"Unsupported localhost scan protocol: {protocol}")

        nmap_artifacts: dict[str, object] = {
            "installed": bool(find_nmap_binary()),
            "path": find_nmap_binary() or "",
            "profile": profile_for_scan(scan_mode, normalized_protocol),
            "ports": [],
            "warnings": [],
            "errors": [],
            "fallback_used": True,
        }
        nmap_results: list[NmapScanResult] = []
        if nmap_artifacts["installed"] and not self.config.dry_run:
            profile_keys = [profile_for_scan(scan_mode, normalized_protocol)]
            if normalized_protocol == "both":
                profile_keys = [
                    profile_for_scan(scan_mode, "tcp"),
                    profile_for_scan("safe", "udp"),
                ]
            for profile_key in profile_keys:
                result = run_nmap_scan(profile_key, target=target)
                nmap_results.append(result)
            nmap_errors = [error for result in nmap_results for error in (result.errors or [])]
            if nmap_results and not nmap_errors:
                tcp_open_ports = sorted(
                    port.port
                    for result in nmap_results
                    for port in result.ports
                    if port.protocol.lower() == "tcp" and port.state == "open"
                )
                udp_open_ports = sorted(
                    port.port
                    for result in nmap_results
                    for port in result.ports
                    if port.protocol.lower() == "udp" and port.state in {"open", "open|filtered"}
                )
                if normalized_protocol == "tcp":
                    open_ports: dict[str, list[int]] | list[int] = tcp_open_ports
                elif normalized_protocol == "udp":
                    open_ports = udp_open_ports
                else:
                    open_ports = {"tcp": tcp_open_ports, "udp": udp_open_ports}
                nmap_artifacts.update(
                    {
                        "profile": ", ".join(result.profile_label for result in nmap_results),
                        "ports": [port.to_dict() for result in nmap_results for port in result.ports],
                        "warnings": [warning for result in nmap_results for warning in (result.warnings or [])],
                        "errors": [],
                        "fallback_used": False,
                        "raw_xml": "\n".join(result.raw_xml for result in nmap_results if result.raw_xml),
                        "command_used": [result.command_used_redacted for result in nmap_results],
                        "sudo_required": any(result.sudo_required for result in nmap_results),
                        "target": target,
                        "timestamp": utc_now_iso(),
                    }
                )
                return {
                    "target": target,
                    "mode": scan_mode,
                    "protocol": normalized_protocol,
                    "open_ports": open_ports,
                    "missing_from_enumeration": [],
                    "errors": [],
                    "scanned_port_count": len([port for result in nmap_results for port in result.ports]),
                    "engine": "nmap",
                    "nmap": nmap_artifacts,
                }
            nmap_artifacts.update(
                {
                    "errors": nmap_errors or [NMAP_INSTALL_MESSAGE],
                    "warnings": [warning for result in nmap_results for warning in (result.warnings or [])],
                    "fallback_used": True,
                }
            )

        ports_to_scan = self._localhost_scan_ports_for_mode(scan_mode)
        tcp_open_ports: list[int] = []
        udp_open_ports: list[int] = []
        errors: list[str] = []
        for port in ports_to_scan:
            try:
                if normalized_protocol in {"tcp", "both"} and self._scan_localhost_port_tcp(target, port):
                    tcp_open_ports.append(port)
                if normalized_protocol in {"udp", "both"} and self._scan_localhost_port_udp(target, port):
                    udp_open_ports.append(port)
            except Exception as exc:
                errors.append(f"port {port}: {exc}")

        if normalized_protocol == "tcp":
            open_ports: dict[str, list[int]] | list[int] = tcp_open_ports
        elif normalized_protocol == "udp":
            open_ports = udp_open_ports
        else:
            open_ports = {"tcp": tcp_open_ports, "udp": udp_open_ports}
        return {
            "target": target,
            "mode": scan_mode,
            "protocol": normalized_protocol,
            "open_ports": open_ports,
            "missing_from_enumeration": [],
            "errors": errors + [str(error) for error in nmap_artifacts.get("errors", [])],
            "scanned_port_count": len(ports_to_scan),
            "engine": "internal_socket",
            "nmap": nmap_artifacts,
        }

    def collect_full_localhost_port_scan(
        self,
        *,
        target_override: str | None = None,
        tcp_ports: list[int] | None = None,
        udp_ports: list[int] | None = None,
        timeout: float = 0.05,
    ) -> dict[str, object]:
        target = self._resolve_localhost_scan_target(target_override)
        tcp_port_list = list(tcp_ports) if tcp_ports is not None else list(range(1, 65536))
        udp_port_list = list(udp_ports) if udp_ports is not None else list(range(1, 65536))
        artifact = self._empty_localhost_full_port_scan_artifact()
        artifact["target"] = target
        artifact["scanned_tcp_count"] = len(tcp_port_list)
        artifact["scanned_udp_count"] = len(udp_port_list)
        if find_nmap_binary() and not self.config.dry_run and tcp_ports is None and udp_ports is None:
            tcp_result = run_nmap_scan("localhost_tcp_full", target=target)
            udp_result = run_nmap_scan("localhost_udp_full", target=target)
            nmap_errors = list(tcp_result.errors or []) + list(udp_result.errors or [])
            if not nmap_errors:
                all_ports = list(tcp_result.ports) + list(udp_result.ports)
                artifact["tcp_open_ports"] = sorted(port.port for port in all_ports if port.protocol.lower() == "tcp" and port.state == "open")
                artifact["udp_responsive_or_unknown_ports"] = sorted(port.port for port in all_ports if port.protocol.lower() == "udp" and port.state in {"open", "open|filtered"})
                artifact["scanned_tcp_count"] = 65535
                artifact["scanned_udp_count"] = 65535
                artifact["engine"] = "nmap"
                artifact["nmap"] = {
                    "installed": True,
                    "path": tcp_result.nmap_path or udp_result.nmap_path,
                    "profiles": [tcp_result.profile_label, udp_result.profile_label],
                    "ports": [port.to_dict() for port in all_ports],
                    "warnings": list(tcp_result.warnings or []) + list(udp_result.warnings or []),
                    "errors": [],
                    "fallback_used": False,
                    "raw_xml": "\n".join(item.raw_xml for item in [tcp_result, udp_result] if item.raw_xml),
                    "command_used": [tcp_result.command_used_redacted, udp_result.command_used_redacted],
                    "sudo_required": tcp_result.sudo_required or udp_result.sudo_required,
                    "target": target,
                    "timestamp": utc_now_iso(),
                }
                return artifact
            artifact["nmap"] = {
                "installed": True,
                "path": tcp_result.nmap_path or udp_result.nmap_path,
                "profiles": [tcp_result.profile_label, udp_result.profile_label],
                "ports": [],
                "warnings": list(tcp_result.warnings or []) + list(udp_result.warnings or []),
                "errors": nmap_errors,
                "fallback_used": True,
                "sudo_required": tcp_result.sudo_required or udp_result.sudo_required,
            }
        tcp_open_ports: list[int] = []
        tcp_banners: dict[int, str] = {}
        udp_responsive_or_unknown_ports: list[int] = []
        errors: list[str] = []
        for port in tcp_port_list:
            try:
                if self._scan_localhost_port_tcp(target, port, timeout=timeout):
                    tcp_open_ports.append(port)
                    banner = self._grab_localhost_tcp_banner(target, port, timeout=timeout)
                    if banner:
                        tcp_banners[port] = banner
            except Exception as exc:
                errors.append(f"tcp:{port}:{exc}")
        for port in udp_port_list:
            try:
                if self._scan_localhost_port_udp(target, port, timeout=timeout):
                    udp_responsive_or_unknown_ports.append(port)
            except Exception as exc:
                errors.append(f"udp:{port}:{exc}")
        artifact["tcp_open_ports"] = tcp_open_ports
        artifact["tcp_banners"] = tcp_banners
        artifact["udp_responsive_or_unknown_ports"] = udp_responsive_or_unknown_ports
        artifact["errors"] = errors
        return artifact

    def _localhost_scan_port_list(self, localhost_scan_artifact: dict[str, object]) -> list[int]:
        open_ports = localhost_scan_artifact.get("open_ports", [])
        if isinstance(open_ports, dict):
            ports: set[int] = set()
            for values in open_ports.values():
                if isinstance(values, list):
                    ports.update(int(port) for port in values)
            return sorted(ports)
        if isinstance(open_ports, list):
            return sorted(int(port) for port in open_ports)
        return []

    def _localhost_scan_tcp_ports(self, localhost_scan_artifact: dict[str, object]) -> list[int]:
        open_ports = localhost_scan_artifact.get("open_ports", [])
        if isinstance(open_ports, dict):
            values = open_ports.get("tcp", [])
            if isinstance(values, list):
                return sorted(int(port) for port in values)
            return []
        if str(localhost_scan_artifact.get("protocol", "")).lower() == "udp":
            return []
        if isinstance(open_ports, list):
            return sorted(int(port) for port in open_ports)
        return []

    def _collect_system_info(self, command_results: list) -> dict:
        info = {
            "macos_version": platform.platform(),
            "hostname": socket.gethostname(),
            "current_user": getpass.getuser(),
            "architecture": platform.machine(),
            "uptime_seconds": int(time.time() - os.stat("/").st_ctime) if Path("/").exists() else 0,
            "security_tools": self._detect_security_tools(),
        }
        for result in command_results:
            command_id = self._result_command_id(result)
            if command_id.startswith("security.") or command_id in {"network.dns_settings", "network.proxy_settings"}:
                info[command_id] = (get_stdout(result) or get_stderr(result)).strip()[:500]
        return info

    def _detect_security_tools(self) -> list[str]:
        tools = []
        for tool in ["/Applications/LuLu.app", "/Applications/KnockKnock.app", "/Applications/BlockBlock.app", "/Library/Objective-See"]:
            if Path(tool).exists():
                tools.append(Path(tool).name)
        return tools

    def _collect_network_info(self, command_results: list) -> dict:
        network = {"active_connections": "", "proxy_settings": "", "dns_settings": "", "remote_login": "", "sharing": ""}
        for result in command_results:
            command_id = self._result_command_id(result)
            text = (get_stdout(result) or get_stderr(result))[:500]
            if command_id == "network.active_connections":
                network["active_connections"] = text
            elif command_id == "network.proxy_settings":
                network["proxy_settings"] = text
            elif command_id == "network.dns_settings":
                network["dns_settings"] = text
        return network

    def _collect_ssh_artifacts(self, users: list[UserSnapshot]) -> dict:
        artifacts = {"users_with_authorized_keys": [], "recent_ssh_files": []}
        for user in users:
            if not user.home:
                continue
            ssh_dir = Path(user.home) / ".ssh"
            if ssh_dir.exists():
                try:
                    for child in sorted(ssh_dir.iterdir())[:20]:
                        if child.is_file():
                            stat_result = child.stat()
                            artifacts["recent_ssh_files"].append({
                                "user": user.username,
                                "path": str(child),
                                "modified_at": str(int(stat_result.st_mtime)),
                                "sha256": self._file_sha256(child) if child.name != "authorized_keys" else "",
                            })
                except OSError:
                    continue
            if user.authorized_keys_count:
                artifacts["users_with_authorized_keys"].append(user.username)
        return artifacts

    def _collect_ports(self, command_results: list) -> CollectorResult:
        del command_results
        collector_result = CollectorResult(
            collector_name="ports",
            artifacts={"ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}},
        )
        collector_result.raw_logs.append(
            RawLogEntry("ports", "collector", utc_now_iso(), None, "", "ports collector started")
        )
        commands = [
            ("lsof_tcp", self._runtime_command("runtime.network.lsof_tcp", "Listening TCP Ports", ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], "Network")),
            ("lsof_udp", self._runtime_command("runtime.network.lsof_udp", "UDP Sockets", ["/usr/sbin/lsof", "-nP", "-iUDP"], "Network")),
            ("netstat_tcp", self._runtime_command("runtime.network.netstat_tcp", "Netstat TCP", ["/usr/sbin/netstat", "-anv", "-p", "tcp"], "Network")),
        ]
        listening: list[PortSnapshot] = []
        errors: list[str] = []
        for parser_name, command in commands:
            collector_result.raw_logs.append(
                RawLogEntry("ports", command.preview, utc_now_iso(), None, "", f"{parser_name} command started")
            )
            result = self.runner.execute(command)
            collector_result.raw_logs.extend(self._command_logs("ports", [result]))
            stdout = get_stdout(result)
            stderr = get_stderr(result)
            exit_code = get_exit_code(result)
            collector_result.raw_logs.append(
                RawLogEntry(
                    "ports",
                    f"{command.preview} debug",
                    utc_now_iso(),
                    exit_code,
                    redact_sensitive_text(stderr[:300], self.config),
                    f"stdout_length={len(stdout)} stderr_length={len(stderr)}",
                )
            )
            if stdout:
                collector_result.raw_logs.append(
                    RawLogEntry("ports", f"{command.preview} stdout preview", utc_now_iso(), exit_code, "", self._debug_stdout_preview(stdout))
                )
            if exit_code not in (0, None):
                error_text = stderr or f"{parser_name} exited with {exit_code}"
                errors.append(error_text)
                collector_result.raw_logs.append(
                    RawLogEntry("ports", command.preview, utc_now_iso(), exit_code, error_text[:300], f"{parser_name} parse count=0")
                )
                continue
            parsed_rows: list[dict[str, object]]
            if parser_name == "lsof_tcp":
                parsed_rows = parse_lsof_listening_output(stdout, self.config)
            elif parser_name == "lsof_udp":
                parsed_rows = parse_lsof_udp_output(stdout, self.config)
            else:
                parsed_rows = parse_netstat_tcp_output(stdout, self.config)
            parsed = [build_port_snapshot(row) for row in parsed_rows]
            collector_result.raw_logs.append(
                RawLogEntry("ports", command.preview, utc_now_iso(), exit_code, "", f"{parser_name} parsed ports={len(parsed)}")
            )
            listening.extend(parsed)
        deduped = {(item.process_name, item.pid, item.local_address, item.port, item.protocol, item.state): item for item in listening}
        listening = list(deduped.values())
        suspicious = [item for item in listening if item.concern]
        collector_result.artifacts["ports"] = {
            "listening": listening,
            "active_connections": [],
            "suspicious_review_needed": suspicious,
            "errors": errors,
        }
        collector_result.raw_logs.append(
            RawLogEntry("ports", "artifact", utc_now_iso(), None, "", f"artifact key written=ports listening={len(listening)} review_needed={len(suspicious)}")
        )
        return collector_result

    def _collect_ports_result(self, command_results: list) -> CollectorResult:
        return self._collect_ports(command_results)

    def _collect_users(self, command_results: list) -> list[UserSnapshot]:
        admin_users = self._parse_admin_users(command_results)
        hidden_users = self._parse_hidden_users(command_results)
        groups_by_user: dict[str, list[str]] = {}
        for group in grp.getgrall():
            for member in group.gr_mem:
                groups_by_user.setdefault(member, []).append(group.gr_name)

        sudo_rule_summary = self._read_sudoers_summary()
        users: list[UserSnapshot] = []
        for record in pwd.getpwall():
            if not self._include_user(record):
                continue
            shell = record.pw_shell or ""
            home = record.pw_dir or ""
            authorized_keys_count, authorized_key_types, authorized_key_comments, authorized_keys_mode = self._authorized_keys_summary(home)
            user_rules = sudo_rule_summary.get(record.pw_name, [])
            users.append(
                UserSnapshot(
                    username=record.pw_name,
                    uid=record.pw_uid,
                    gid=record.pw_gid,
                    shell=shell,
                    home=home,
                    hidden=record.pw_name in hidden_users,
                    admin=record.pw_name in admin_users,
                    locked=False,
                    disabled=shell in {"", "/usr/bin/false", "/usr/bin/nologin"},
                    unusual_uid=record.pw_uid not in {0} and record.pw_uid < 500,
                    unusual_gid=record.pw_gid < 20,
                    shell_enabled=shell not in {"", "/usr/bin/false", "/usr/bin/nologin"},
                    suspicious_home=bool(home) and not home.startswith("/Users/") and record.pw_name not in {"root", "nobody"},
                    groups=sorted(groups_by_user.get(record.pw_name, [])),
                    authorized_keys_count=authorized_keys_count,
                    authorized_key_types=authorized_key_types,
                    authorized_key_comments=authorized_key_comments,
                    authorized_keys_mode=authorized_keys_mode,
                    sudo_rule_count=len(user_rules),
                    sudo_rule_sources=sorted({rule["source"] for rule in user_rules}),
                )
            )
        return sorted(users, key=lambda item: (item.uid, item.username))

    def _collect_processes(self, command_results: list) -> CollectorResult:
        del command_results
        collector_result = CollectorResult(
            collector_name="processes",
            artifacts={"processes": {"all": [], "suspicious": [], "errors": []}, "command_results": []},
        )
        collector_result.raw_logs.append(
            RawLogEntry("processes", "collector", utc_now_iso(), None, "", "processes collector started")
        )
        command = self._runtime_command(
            "runtime.processes.ps_axo",
            "Process List",
            ["/bin/ps", "-axo", "user=,pid=,ppid=,comm=,args="],
            "Files & Processes",
        )
        collector_result.raw_logs.append(
            RawLogEntry("processes", command.preview, utc_now_iso(), None, "", "ps_axo command started")
        )
        result = self.runner.execute(command)
        collector_result.raw_logs.extend(self._command_logs("processes", [result]))
        stdout = get_stdout(result)
        stderr = get_stderr(result)
        exit_code = get_exit_code(result)
        collector_result.raw_logs.append(
            RawLogEntry(
                "processes",
                f"{command.preview} debug",
                utc_now_iso(),
                exit_code,
                redact_sensitive_text(stderr[:300], self.config),
                f"stdout_length={len(stdout)} stderr_length={len(stderr)}",
            )
        )
        if stdout:
            collector_result.raw_logs.append(
                RawLogEntry("processes", f"{command.preview} stdout preview", utc_now_iso(), exit_code, "", self._debug_stdout_preview(stdout))
            )
        if exit_code not in (0, None):
            error_text = stderr[:300] or stdout[:300] or "process collection command failed"
            collector_result.artifacts["processes"]["errors"].append(error_text)
            collector_result.raw_logs.append(
                RawLogEntry("processes", command.preview, utc_now_iso(), exit_code, error_text, "parsed processes=0")
            )
            return collector_result

        process_snapshots: list[ProcessSnapshot] = []
        errors: list[str] = []
        extra_results = []
        codesign_available = Path("/usr/bin/codesign").exists()
        for record in parse_ps_axo_output(stdout):
            try:
                signed_status = "unknown"
                command_path = str(record.get("command_path") or record.get("comm") or record.get("path") or "")
                if not command_path:
                    errors.append(f"missing command path for pid={record.get('pid', '?')}")
                    continue
                path = Path(command_path)
                if path.is_file() and codesign_available:
                    signed_status, codesign_result = self._codesign_status(path, f"process.codesign.{record['pid']}")
                    if codesign_result is not None:
                        extra_results.append(codesign_result)
                process_snapshots.append(build_process_snapshot_from_row(record, signed_status))
            except Exception as exc:
                errors.append(str(exc))
        suspicious = [item for item in process_snapshots if item.trust_level != "trusted"]
        collector_result.raw_logs.append(
            RawLogEntry("processes", command.preview, utc_now_iso(), exit_code, "", f"parsed processes={len(process_snapshots)} suspicious={len(suspicious)}")
        )
        collector_result.artifacts["processes"] = {
            "all": process_snapshots,
            "suspicious": suspicious,
            "errors": errors,
        }
        collector_result.artifacts["command_results"] = extra_results
        collector_result.raw_logs.append(
            RawLogEntry("processes", "artifact", utc_now_iso(), None, "", f"artifact key written=processes all={len(process_snapshots)} suspicious={len(suspicious)}")
        )
        return collector_result

    def _collect_processes_result(self, command_results: list) -> CollectorResult:
        return self._collect_processes(command_results)

    def _collect_intrusion_methods_result(self, process_snapshots: list[ProcessSnapshot], launch_snapshots: list[LaunchItemSnapshot]) -> CollectorResult:
        collector_result = CollectorResult(
            collector_name="intrusion_methods",
            artifacts={"intrusion_methods": {"persistence": [], "memory": [], "errors": []}, "command_results": []},
        )
        persistence_findings = []
        for item in launch_snapshots:
            finding = analyze_launch_item_for_persistence(item)
            if finding is not None:
                persistence_findings.append(finding.to_dict())
        for finding in scan_persistence_methods():
            persistence_findings.append(finding.to_dict())

        memory_findings = []
        errors: list[str] = []
        extra_results = []
        vmmap_path = Path("/usr/bin/vmmap")
        if vmmap_path.exists():
            candidates = [
                item
                for item in process_snapshots
                if item.pid is not None and (item.trust_level != "trusted" or any(reason in {"unsigned_process_binary", "process_in_writable_path", "process_in_user_space"} for reason in item.reasons))
            ][:8]
            for item in candidates:
                command = self._runtime_command(
                    f"runtime.memory.vmmap.{item.pid}",
                    f"Process Memory Map pid {item.pid}",
                    [str(vmmap_path), "-interleaved", str(item.pid)],
                    "Files & Processes",
                    timeout_seconds=8,
                )
                result = self.runner.execute(command)
                extra_results.append(result)
                stdout = get_stdout(result)
                stderr = get_stderr(result)
                exit_code = get_exit_code(result)
                if exit_code not in (0, None):
                    errors.append(f"vmmap pid={item.pid} failed: {(stderr or stdout)[:160]}")
                    continue
                for finding in analyze_vmmap_output(item.pid, item.process_name, item.command_path, stdout):
                    memory_findings.append(finding.to_dict())
        else:
            errors.append("vmmap unavailable; memory-shellcode heuristic coverage skipped")

        collector_result.artifacts["intrusion_methods"] = {
            "persistence": persistence_findings,
            "memory": memory_findings,
            "errors": errors,
        }
        collector_result.artifacts["command_results"] = extra_results
        collector_result.raw_logs.append(
            RawLogEntry(
                "intrusion_methods",
                "ATT&CK persistence and vmmap heuristics",
                utc_now_iso(),
                None,
                "; ".join(errors)[:300],
                f"persistence={len(persistence_findings)} memory={len(memory_findings)}",
            )
        )
        return collector_result

    def _collect_launch_items(self) -> list[LaunchItemSnapshot]:
        snapshots: list[LaunchItemSnapshot] = []
        for root in ["~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]:
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

    def _include_user(self, record: pwd.struct_passwd) -> bool:
        return record.pw_uid >= 500 or record.pw_name in {"root", "nobody"} or record.pw_dir.startswith("/Users/")

    def _parse_admin_users(self, command_results: list) -> set[str]:
        for result in command_results:
            if self._result_command_id(result) == "accounts.admin_users" and "GroupMembership:" in get_stdout(result):
                return set(get_stdout(result).split("GroupMembership:", 1)[1].strip().split())
        return set()

    def _parse_hidden_users(self, command_results: list) -> set[str]:
        for result in command_results:
            if self._result_command_id(result) == "accounts.hidden_users":
                lines = [line.strip().strip('",()') for line in get_stdout(result).splitlines()]
                return {line for line in lines if line and line not in {"HiddenUsersList =", ";"}}
        return set()

    def _authorized_keys_summary(self, home: str) -> tuple[int, list[str], list[str], str]:
        if not home:
            return 0, [], [], ""
        path = Path(home) / ".ssh" / "authorized_keys"
        if not path.exists() or not os.access(path, os.R_OK):
            return 0, [], [], ""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            st = path.stat()
        except OSError:
            return 0, [], [], ""
        count, key_types, comments = summarize_authorized_keys(lines)
        return count, key_types, comments[:3], format(stat.S_IMODE(st.st_mode), "04o")

    def _collect_history_indicators(self, users: list[UserSnapshot]) -> list[HistoryIndicator]:
        indicators: list[HistoryIndicator] = []
        for user in users:
            if not user.home:
                continue
            for filename, shell_type in [(".zsh_history", "zsh"), (".bash_history", "bash"), (".sh_history", "sh")]:
                path = Path(user.home).expanduser() / filename
                if not path.exists() or not os.access(path, os.R_OK) or not path.is_file():
                    continue
                try:
                    history_text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                indicators.extend(extract_history_indicators(history_text, str(path), shell_type, self.config))
        return indicators

    def _collect_permission_snapshots(self, users: list[UserSnapshot]) -> list[PermissionSnapshot]:
        snapshots: list[PermissionSnapshot] = []
        paths = set()
        for user in users:
            if user.home:
                home = Path(user.home)
                paths.update(
                    {
                        home / ".ssh",
                        home / ".ssh" / "authorized_keys",
                        home / ".zshrc",
                        home / ".zprofile",
                        home / ".bash_profile",
                        home / ".bashrc",
                        home / "Library" / "LaunchAgents",
                    }
                )
        paths.update(Path(path).expanduser() for path in ["/Library/LaunchAgents", "/Library/LaunchDaemons", "/Users/Shared"])
        for path in sorted(paths):
            try:
                st = path.stat()
            except OSError:
                continue
            issue = detect_weak_permission(str(path), st.st_mode)
            if issue is not None:
                snapshots.append(issue)
        return snapshots

    def _collect_file_issues(self) -> tuple[list[FileIssueSnapshot], set[str], list]:
        issues: list[FileIssueSnapshot] = []
        launch_items: set[str] = set()
        extra_results = []
        codesign_available = Path("/usr/bin/codesign").exists()
        for directory in TARGET_DIRECTORIES:
            root = Path(directory).expanduser()
            if not root.exists():
                continue
            try:
                root_mode = root.stat().st_mode
            except OSError:
                root_mode = 0
            directory_world_writable = bool(root_mode & stat.S_IWOTH)
            for path in self._walk_limited(root, max_depth=2):
                try:
                    st = path.stat()
                except OSError:
                    continue
                if path.suffix == ".plist" and ("LaunchAgents" in str(path) or "LaunchDaemons" in str(path)):
                    launch_items.add(path.name)
                executable = bool(st.st_mode & stat.S_IXUSR) and path.is_file()
                world_writable = bool(st.st_mode & stat.S_IWOTH)
                hidden = path.name.startswith(".")
                recent = (self._now_epoch() - st.st_mtime) <= 7 * 86400
                signed_status = "unknown"
                sha256 = self._file_sha256(path) if path.is_file() and executable else ""
                if executable and recent and codesign_available and path.is_file():
                    signed_status, result = self._codesign_status(path, f"files.codesign.{path.name}")
                    if result is not None:
                        extra_results.append(result)
                writable_exec = detect_suspicious_writable_executable(str(path), directory_world_writable=directory_world_writable, executable=executable)
                if writable_exec is not None:
                    writable_exec.modified_at = str(int(st.st_mtime))
                    writable_exec.signed_status = signed_status
                    writable_exec.sha256 = sha256
                    issues.append(writable_exec)
                issue = detect_suspicious_file(
                    str(path),
                    executable=executable and recent,
                    world_writable=world_writable,
                    hidden=hidden and executable,
                    signed_status=signed_status,
                    modified_at=str(int(st.st_mtime)),
                )
                if issue is not None:
                    issue.sha256 = sha256
                    issues.append(issue)
        deduped = {item.key(): item for item in issues}
        return list(deduped.values()), launch_items, extra_results

    def _collect_file_issues_result(self) -> CollectorResult:
        file_issues, launch_items, extra_results = self._collect_file_issues()
        return CollectorResult(
            collector_name="files",
            artifacts={
                "file_issues": file_issues,
                "launch_items": sorted(launch_items),
                "command_results": extra_results,
            },
        )

    def _read_sudoers_summary(self) -> dict[str, list[dict[str, str]]]:
        principals: dict[str, list[dict[str, str]]] = {}
        paths = [Path("/etc/sudoers")]
        sudoers_dir = Path("/etc/sudoers.d")
        if sudoers_dir.exists() and sudoers_dir.is_dir():
            paths.extend(sorted(item for item in sudoers_dir.iterdir() if item.is_file())[:100])
        for path in paths:
            if not path.exists() or not os.access(path, os.R_OK):
                continue
            try:
                rules = parse_sudoers(path.read_text(encoding="utf-8", errors="replace"), str(path))
            except OSError:
                continue
            for rule in rules:
                principals.setdefault(rule["principal"], []).append(rule)
        return principals

    def _collect_sudoers_findings(self, users: list[UserSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        rules_by_principal = self._read_sudoers_summary()
        for principal, rules in rules_by_principal.items():
            for rule in rules:
                risk = detect_sudoers_risk(rule)
                if risk is None:
                    continue
                severity, why = risk
                findings.append(
                    self._finding(
                        category="Accounts & Privileges",
                        title=f"Sudoers Rule Review: {principal}",
                        severity=severity,
                        description="A readable sudoers rule grants broad privileges and should be reviewed.",
                        evidence=f"{principal} {rule['spec']} ({rule['source']})",
                        evidence_summary=f"{principal} has a broad sudoers rule in {rule['source']}",
                        raw_evidence_ref=f"sudoers:{rule['source']}:{principal}",
                        why_this_matters=why,
                        false_positive_notes="Administrative workstations often contain intentional sudo rules for support or automation.",
                        recommended_next_steps="Verify the rule owner, scope, and whether passwordless or broad sudo access is still required.",
                        what_can_go_wrong="Removing or narrowing a legitimate sudo rule without validation can break administration, deployment, or recovery workflows.",
                        command_used="local readable sudoers file review",
                    )
                )
        return findings

    def _walk_limited(self, root: Path, max_depth: int) -> list[Path]:
        results: list[Path] = []
        stack = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            results.append(current)
            if depth >= max_depth or not current.is_dir():
                continue
            try:
                children = list(current.iterdir())
            except OSError:
                continue
            for child in children[:100]:
                stack.append((child, depth + 1))
        return results

    def _file_sha256(self, path: Path) -> str:
        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(8192)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return ""

    def _codesign_status(self, path: Path, command_id: str) -> tuple[str, object | None]:
        command = AuditCommand(
            id=command_id,
            name=f"Codesign Check: {path.name}",
            description="Checks whether a candidate executable has a code signature.",
            command=["/usr/bin/codesign", "-dv", str(path)],
            privilege_required=False,
            risk_level="safe",
            mutates_system=False,
            timeout_seconds=5,
            collection_warning="Executable path may reveal installed tooling.",
            failure_modes=["codesign unavailable.", "Unsigned file.", "Permission denied."],
            user_disclaimer="Read-only signature metadata inspection.",
            safer_alternative="Inspect code signatures manually with codesign.",
            category="Files & Processes",
        )
        result = self.runner.execute(command)
        if self._result_dry_run(result):
            return "unknown", result
        if get_exit_code(result) == 0:
            return "signed", result
        return "unsigned", result

    def _findings_for_ports(self, ports: list[PortSnapshot]) -> list[Finding]:
        return [
            self._finding(
                category="Network",
                title=f"Concerning Listening Port {port.port}",
                severity=port.severity,
                description=f"{port.process_name} (PID {port.pid}) is listening on {port.local_address}.",
                evidence=f"{port.protocol} {port.local_address} {port.state}".strip(),
                evidence_summary=f"{port.process_name} pid={port.pid} local={port.local_address} port={port.port}",
                raw_evidence_ref=f"network.listening_ports:{port.pid}:{port.port}",
                why_this_matters=port.concern,
                false_positive_notes="A listening port alone is not proof of compromise. Development tools and remote administration products may bind expected listeners.",
                recommended_next_steps=port.recommended_next_checks,
                what_can_go_wrong="Stopping or uninstalling the wrong service can interrupt legitimate development, management, or sharing workflows.",
                command_used=self.registry["network.listening_ports"].preview,
            )
            for port in ports
            if port.concern
        ]

    def _findings_for_localhost_scan(self, ports_artifact: dict, localhost_scan_artifact: dict[str, object]) -> list[Finding]:
        enumerated_ports = {
            item.port
            for item in ports_artifact.get("listening", [])
            if getattr(item, "protocol", "").upper() == "TCP" and item.port is not None
        }
        scanned_open_ports = self._localhost_scan_tcp_ports(localhost_scan_artifact)
        missing_ports = sorted(port for port in scanned_open_ports if port not in enumerated_ports)
        localhost_scan_artifact["missing_from_enumeration"] = missing_ports
        return [
            self._finding(
                category="Localhost Port Scan",
                title="Visibility mismatch detected",
                severity="high" if port in self.config.concerning_ports else "medium",
                description="A localhost-only active port scan found a responsive port that was not present in the listening-port enumeration output.",
                evidence=str(port),
                evidence_summary=f"localhost port {port} responded but was not enumerated",
                raw_evidence_ref=f"localhost_scan:{port}",
                why_this_matters="A mismatch between active probing and local enumeration can indicate transient listeners, parser issues, permission gaps, or a service that needs closer validation.",
                false_positive_notes="Race conditions, permission issues, transient services, parser bugs, or sandboxing can cause mismatches.",
                recommended_next_steps="Investigate with multiple local tools, compare against baseline, and identify the owning service before taking action.",
                what_can_go_wrong="Do not assume compromise from this alone. Killing or deleting unknown services can break legitimate software.",
                command_used=str(localhost_scan_artifact.get("engine", "localhost port scan")),
            )
            for port in missing_ports
        ]

    def _findings_for_system_info(self, system_info: dict) -> list[Finding]:
        findings: list[Finding] = []
        if system_info.get("security.firewall_status", "").lower().find("disabled") != -1:
            return findings
        findings.append(self._finding(
            category="System Information",
            title="System Context Captured",
            severity="info",
            description="Collected local macOS host context for this read-only scan.",
            evidence=f"host={system_info.get('hostname')} user={system_info.get('current_user')} arch={system_info.get('architecture')}",
            evidence_summary=f"{system_info.get('hostname')} {system_info.get('macos_version')}",
            raw_evidence_ref="system_info",
            why_this_matters="Host context is useful for baseline comparison and triage.",
            false_positive_notes="This is informational only.",
            recommended_next_steps="Review the system and security status values alongside the findings below.",
            what_can_go_wrong="Treating informational context as proof of security can be misleading.",
            command_used="platform/socket/getpass + read-only security checks",
        ))
        return findings

    def _findings_for_network_info(self, network_info: dict) -> list[Finding]:
        findings: list[Finding] = []
        if network_info.get("proxy_settings"):
            findings.append(self._finding(
                category="Network",
                title="Proxy Settings Captured",
                severity="info",
                description="Proxy configuration was collected for review.",
                evidence=network_info["proxy_settings"],
                evidence_summary="Proxy settings collected.",
                raw_evidence_ref="network:proxy_settings",
                why_this_matters="Unexpected proxies can redirect traffic or indicate management tooling.",
                false_positive_notes="Corporate or developer environments often configure proxies intentionally.",
                recommended_next_steps="Confirm the proxy host and scope are expected for this system.",
                what_can_go_wrong="Removing a legitimate proxy can break browsing, package installs, or enterprise access.",
                command_used="network.proxy_settings",
            ))
        return findings

    def _findings_for_ssh(self, ssh_artifacts: dict) -> list[Finding]:
        findings: list[Finding] = []
        for item in ssh_artifacts.get("recent_ssh_files", []):
            if item.get("path", "").endswith("authorized_keys"):
                continue
            findings.append(self._finding(
                category="SSH",
                title=f"Recent SSH File: {Path(item['path']).name}",
                severity="info",
                description="A readable SSH-related file was recently observed for a local user.",
                evidence=f"{item['path']} modified_at={item['modified_at']}",
                evidence_summary=f"{item['user']} SSH file {Path(item['path']).name}",
                raw_evidence_ref=f"ssh:{item['path']}",
                why_this_matters="Unexpected SSH file changes can affect remote access behavior.",
                false_positive_notes="Legitimate key rotation or SSH configuration changes can cause this.",
                recommended_next_steps="Verify the file owner, change timing, and whether the change was expected.",
                what_can_go_wrong="Deleting the wrong SSH file can break legitimate remote administration access.",
                command_used="ssh metadata inspection",
            ))
        return findings

    def _findings_for_users(self, users: list[UserSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        for user in users:
            if user.hidden:
                findings.append(self._finding(
                    category="Accounts & Privileges",
                    title=f"Hidden User Account: {user.username}",
                    severity="medium",
                    description="A hidden account is configured on this Mac.",
                    evidence=f"user={user.username} uid={user.uid} shell={user.shell}",
                    evidence_summary=f"Hidden user {user.username} with shell {user.shell}",
                    raw_evidence_ref=f"user:{user.username}",
                    why_this_matters="Hidden accounts can complicate inventory and incident review if they are not expected.",
                    false_positive_notes="Some management tools and service accounts are intentionally hidden.",
                    recommended_next_steps="Verify the account owner, purpose, last use, and whether hidden login behavior is intentional.",
                    what_can_go_wrong="Disabling a legitimate service account without validation can break device management or automation.",
                    command_used="pwd/grp + hidden user preference review",
                ))
            if user.admin and user.uid >= 500:
                findings.append(self._finding(
                    category="Accounts & Privileges",
                    title=f"Admin-Capable User: {user.username}",
                    severity="info" if user.username == os.getenv("USER") else "low",
                    description="This local user is a member of the admin group.",
                    evidence=f"user={user.username} uid={user.uid} groups={','.join(user.groups)}",
                    evidence_summary=f"Admin user {user.username}",
                    raw_evidence_ref=f"user:{user.username}",
                    why_this_matters="Admin accounts increase the impact of account compromise.",
                    false_positive_notes="Primary user accounts are often intentionally administrative.",
                    recommended_next_steps="Confirm the account is expected and protected with strong authentication.",
                    what_can_go_wrong="Removing admin rights from the wrong user may lock out legitimate administration.",
                    command_used=self.registry["accounts.admin_users"].preview,
                ))
            if user.unusual_uid or user.suspicious_home:
                findings.append(self._finding(
                    category="Accounts & Privileges",
                    title=f"User Requires Review: {user.username}",
                    severity="medium",
                    description="The account has an unusual UID/GID or a nonstandard home directory.",
                    evidence=f"user={user.username} uid={user.uid} gid={user.gid} home={user.home}",
                    evidence_summary=f"{user.username} uid={user.uid} home={user.home}",
                    raw_evidence_ref=f"user:{user.username}",
                    why_this_matters="Unexpected account metadata can indicate legacy service users, misconfiguration, or persistence.",
                    false_positive_notes="Managed Macs and developer tooling sometimes create service accounts with unusual metadata.",
                    recommended_next_steps="Check account creation date, ownership, shell access, and whether the home path is documented.",
                    what_can_go_wrong="Removing the wrong service account can break system services or management agents.",
                    command_used="pwd/grp local user inspection",
                ))
            if user.authorized_keys_count:
                findings.append(self._finding(
                    category="Accounts & Privileges",
                    title=f"SSH Authorized Keys Present: {user.username}",
                    severity="info",
                    description="One or more SSH authorized keys are present for this account.",
                    evidence=f"user={user.username} count={user.authorized_keys_count} types={','.join(user.authorized_key_types)} mode={user.authorized_keys_mode}",
                    evidence_summary=f"{user.username} has {user.authorized_keys_count} authorized key(s).",
                    raw_evidence_ref=f"authorized_keys:{user.username}",
                    why_this_matters="Authorized keys enable key-based remote login if SSH access is enabled and reachable.",
                    false_positive_notes="Developer and administration workflows often rely on authorized keys intentionally.",
                    recommended_next_steps="Confirm each key owner, whether SSH is enabled, and whether the file permissions are appropriately restrictive.",
                    what_can_go_wrong="Removing the wrong authorized key can lock out a legitimate administrator or automation workflow.",
                    command_used="local authorized_keys summary only",
                ))
            if user.sudo_rule_count:
                findings.append(self._finding(
                    category="Accounts & Privileges",
                    title=f"Sudoers Entries Present: {user.username}",
                    severity="info",
                    description="Readable sudoers configuration references this account.",
                    evidence=f"user={user.username} sources={','.join(user.sudo_rule_sources)} count={user.sudo_rule_count}",
                    evidence_summary=f"{user.username} appears in {user.sudo_rule_count} readable sudoers rule(s).",
                    raw_evidence_ref=f"sudoers_user:{user.username}",
                    why_this_matters="Sudo access can materially increase the impact of account misuse.",
                    false_positive_notes="Administrative accounts frequently have legitimate sudo access.",
                    recommended_next_steps="Review the exact sudo scope and confirm that it matches current administrative need.",
                    what_can_go_wrong="Removing legitimate sudo access can block support, deployment, or recovery tasks.",
                    command_used="local readable sudoers file review",
                ))
        return findings

    def _findings_for_history(self, indicators: list[HistoryIndicator]) -> list[Finding]:
        findings: list[Finding] = []
        for indicator in indicators:
            severity = "high" if indicator.pattern_id in {"reverse_shell", "curl_pipe_sh", "wget_pipe_sh"} else "medium"
            findings.append(self._finding(
                category="Shell History",
                title=f"Suspicious History Indicator: {indicator.pattern_id}",
                severity=severity,
                description="A shell history entry matched a suspicious execution or persistence pattern.",
                evidence=indicator.snippet,
                evidence_summary=f"{indicator.pattern_id} matched {indicator.match_count} time(s) in {indicator.shell_type} history.",
                raw_evidence_ref=f"history:{indicator.source_path}:{indicator.pattern_id}",
                why_this_matters=indicator.warning,
                false_positive_notes="Administrators and developers may legitimately use these commands during support or testing.",
                recommended_next_steps="Review the timeframe, user intent, and adjacent audit logs before taking action. Collect full command context only with informed consent.",
                what_can_go_wrong="Overreacting to a single history pattern can disrupt legitimate administrative workflows and may still miss context such as lab or recovery work.",
                command_used="local file read with redacted snippet storage only",
            ))
        return findings

    def _findings_for_permissions(self, permission_snapshots: list[PermissionSnapshot]) -> list[Finding]:
        return [
            self._finding(
                category="Permissions",
                title=f"Weak Permissions: {Path(item.path).name}",
                severity=item.severity,
                description=item.issue,
                evidence=f"{item.path} mode={item.mode}",
                evidence_summary=f"{item.path} mode {item.mode}",
                raw_evidence_ref=f"permission:{item.path}",
                why_this_matters="Weak permissions can let other local users tamper with startup files, SSH trust, or persistence locations.",
                false_positive_notes="Shared lab systems may intentionally relax permissions in some paths, though that is still worth review.",
                recommended_next_steps="Confirm file ownership and compare the observed mode against the intended hardening baseline.",
                what_can_go_wrong="Blindly tightening permissions on the wrong shared path can break multi-user workflows or managed tooling.",
                command_used="local stat inspection",
            )
            for item in permission_snapshots
        ]

    def _findings_for_processes(self, process_snapshots: list[ProcessSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        for item in process_snapshots:
            if item.trust_level == "trusted":
                continue
            severity = "high" if item.trust_level == "untrusted" else "medium"
            findings.append(self._finding(
                category="Processes",
                title=f"Process Trust Review: {item.process_name}",
                severity=severity,
                description="A running process was observed in a nonstandard or suspicious location.",
                evidence=f"pid={item.pid} user={item.user} path={item.command_path} trust_score={item.trust_score} reasons={','.join(item.reasons)}",
                evidence_summary=f"{item.process_name} pid={item.pid} trust={item.trust_level} score={item.trust_score}",
                raw_evidence_ref=f"process:{item.pid}:{item.command_path}",
                why_this_matters="Processes running from writable or unusual paths can be signs of staging, persistence, or weak software hygiene. The binary trust score helps prioritize review.",
                false_positive_notes="Developer tooling and custom internal utilities may run from user-space or unsigned paths intentionally.",
                recommended_next_steps=f"Verify the binary owner, package origin, code signature, and whether the process was launched by an expected parent. Trust summary: {item.trust_summary}",
                what_can_go_wrong="Killing the wrong process can interrupt active work or management agents before evidence is collected.",
                command_used=self.registry["files.running_processes"].preview,
            ))
        return findings

    def _findings_for_launch_items(self, launch_snapshots: list[LaunchItemSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        for item in launch_snapshots:
            if not item.suspicious:
                continue
            findings.append(self._finding(
                category="Persistence",
                title=f"Suspicious Launch Item: {item.label}",
                severity="high",
                description="A LaunchAgent or LaunchDaemon references a suspicious path or execution pattern.",
                evidence=f"{item.path} -> {item.program} reasons={','.join(item.reasons)}",
                evidence_summary=f"{item.label} launches {item.program}",
                raw_evidence_ref=f"launch_item:{item.path}",
                why_this_matters="Launch items provide persistence and can restart unwanted software automatically.",
                false_positive_notes="Enterprise management or internal tooling can legitimately use launchd with non-Apple labels or user-space binaries.",
                recommended_next_steps="Review the plist owner, creation time, referenced binary, and whether the launch item matches known installed software.",
                what_can_go_wrong="Disabling a legitimate launch item can break login workflows, management agents, or installed software updates.",
                command_used="local plist parsing",
            ))
        return findings

    def _findings_for_intrusion_methods(self, intrusion_methods: dict) -> list[Finding]:
        findings: list[Finding] = []
        for item in intrusion_methods.get("persistence", []) if isinstance(intrusion_methods, dict) else []:
            findings.append(self._finding(
                category="Persistence",
                title=str(item.get("title", "ATT&CK Persistence Review")),
                severity=str(item.get("severity", "medium")),
                description="Known macOS persistence method or high-risk persistence configuration was observed.",
                evidence=str(item.get("evidence", "")),
                evidence_summary=f"{item.get('method', 'persistence')} {item.get('path', '')} confidence={item.get('confidence', 'medium')} mitre={item.get('mitre', '')}",
                raw_evidence_ref=f"intrusion_method:persistence:{item.get('path', '')}",
                why_this_matters="Persistence lets an intruder regain execution after reboot or login. Writable paths, download-and-execute commands, login hooks, and launchd auto-start keys raise investigation priority.",
                false_positive_notes="Management tools, VPN clients, endpoint agents, and developer automation can legitimately use these mechanisms.",
                recommended_next_steps="Preserve the plist or script, verify owner and signature of the referenced executable, correlate with recent execution/network events, and confirm whether the persistence method is approved.",
                what_can_go_wrong="Removing persistence without preserving evidence can destroy timeline context or break managed software.",
                command_used="ATT&CK persistence heuristic scan",
            ))
        for item in intrusion_methods.get("memory", []) if isinstance(intrusion_methods, dict) else []:
            findings.append(self._finding(
                category="Execution",
                title=str(item.get("title", "Possible In-Memory Code Execution")),
                severity=str(item.get("severity", "high")),
                description="A process memory map contains shellcode-like executable memory characteristics.",
                evidence=str(item.get("evidence", "")),
                evidence_summary=f"pid={item.get('pid', '')} process={item.get('process_name', '')} reasons={','.join(item.get('reasons', []))} mitre={item.get('mitre', '')}",
                raw_evidence_ref=f"intrusion_method:memory:{item.get('pid', '')}",
                why_this_matters="Executable anonymous, heap, stack, or writable memory can be consistent with injected shellcode, reflective loading, JIT engines, or other in-memory execution. This is a high-value review signal, not proof of compromise by itself.",
                false_positive_notes="Browsers, language runtimes, emulators, security products, and JIT-enabled software may legitimately allocate executable memory.",
                recommended_next_steps="Preserve a process listing, vmmap output, network connections, parent process, file hash, and code-signing status before terminating the process.",
                what_can_go_wrong="Killing the process first can destroy volatile memory evidence needed for forensic review.",
                command_used="/usr/bin/vmmap -interleaved <pid>",
            ))
        return findings

    def _findings_for_files(self, file_issues: list[FileIssueSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        for item in file_issues:
            severity = "high" if ("unsigned" in item.issue_type or "world_writable" in item.issue_type or "writable_directory_executable" in item.issue_type) else "medium"
            findings.append(self._finding(
                category="File/Directory Issues",
                title=f"Suspicious File or Directory: {Path(item.path).name}",
                severity=severity,
                description="A targeted high-risk path contains a recently modified or suspicious executable or writable item.",
                evidence=f"{item.path} [{item.issue_type}] trust_score={item.trust_score}",
                evidence_summary=f"{item.path} flagged as {item.issue_type} score={item.trust_score}",
                raw_evidence_ref=f"file:{item.path}",
                why_this_matters="High-risk directories are common persistence and staging locations. Binary trust scoring helps distinguish likely low-trust executables from review-only cases.",
                false_positive_notes="Package managers, installers, and developer tools can legitimately create unsigned or recently modified binaries in these paths.",
                recommended_next_steps=f"Check the owning package, signature metadata, modification time, and whether the file aligns with expected software inventory. Trust summary: {item.trust_summary}",
                what_can_go_wrong="Deleting or quarantining the wrong binary can break installed applications, management agents, or developer tooling.",
                command_used="targeted local filesystem inspection",
            ))
        return findings

    def _findings_for_security_commands(self, command_results: list) -> list[Finding]:
        findings: list[Finding] = []
        for result in command_results:
            text = "\n".join(part for part in [get_stdout(result).strip(), get_stderr(result).strip()] if part)
            if not text:
                continue
            command_id = self._result_command_id(result)
            if command_id == "security.firewall_status" and "disabled" in text.lower():
                findings.append(self._security_finding("Firewall Disabled", "Network", "high", text, self.registry[command_id].preview, "Disabled firewall coverage can increase inbound exposure."))
            if command_id == "security.filevault" and "off" in text.lower():
                findings.append(self._security_finding("FileVault Disabled", "macOS Security", "high", text, self.registry[command_id].preview, "Unencrypted storage increases risk if the device is lost or stolen."))
            if command_id == "security.gatekeeper" and "disabled" in text.lower():
                findings.append(self._security_finding("Gatekeeper Disabled", "macOS Security", "high", text, self.registry[command_id].preview, "App assessment protections appear reduced."))
            if command_id == "security.sip_status" and "disabled" in text.lower():
                findings.append(self._security_finding("SIP Disabled", "macOS Security", "critical", text, self.registry[command_id].preview, "Core platform protections are reduced."))
        return findings

    def _security_finding(self, title: str, category: str, severity: str, evidence: str, command_used: str, why: str) -> Finding:
        return self._finding(
            category=category,
            title=title,
            severity=severity,
            description=title,
            evidence=evidence,
            evidence_summary=evidence.splitlines()[0][:200],
            raw_evidence_ref=f"command:{title}",
            why_this_matters=why,
            false_positive_notes="This may be an intentional configuration for testing or compatibility, but it reduces a platform safeguard.",
            recommended_next_steps="Verify the setting was intentionally changed and review surrounding administrative activity.",
            what_can_go_wrong="Re-enabling a hardening control without checking software dependencies can interrupt workflows that relied on the weaker setting.",
            command_used=command_used,
        )

    def _findings_for_comparison(self, comparison: BaselineComparison) -> list[Finding]:
        findings: list[Finding] = []
        if comparison.total_changes():
            summary_severity = "high" if comparison.drift_label == "high drift" else "medium" if comparison.drift_label == "moderate drift" else "info"
            findings.append(self._finding(
                category="Baseline Comparison",
                title="Baseline Drift Detected",
                severity=summary_severity,
                description=comparison.drift_summary or "Differences from the previous scan were observed.",
                evidence=f"drift_score={comparison.drift_score} label={comparison.drift_label} high_risk_changes={comparison.high_risk_change_count}",
                evidence_summary=comparison.drift_summary or f"Drift score {comparison.drift_score}/100",
                raw_evidence_ref="baseline:drift_summary",
                why_this_matters="A cluster of changes across users, processes, launch items, files, or network listeners can indicate recent administrative activity or suspicious drift.",
                false_positive_notes="System updates, package installs, and approved administrative changes can legitimately cause baseline drift.",
                recommended_next_steps="Review the specific deltas below, prioritize high-risk categories first, and confirm whether the changes match expected maintenance or user activity.",
                what_can_go_wrong="Ignoring drift can hide meaningful change over time, but overreacting to expected maintenance can waste investigation time.",
                command_used="baseline comparison",
            ))
        groups = [
            ("New Listening Ports Since Last Scan", comparison.new_ports),
            ("Removed Listening Ports Since Last Scan", comparison.removed_ports),
            ("New Users Since Last Scan", comparison.new_users),
            ("Removed Users Since Last Scan", comparison.removed_users),
            ("New Admin Users Since Last Scan", comparison.new_admin_users),
            ("New Launch Items Since Last Scan", comparison.new_launch_items),
            ("Removed Launch Items Since Last Scan", comparison.removed_launch_items),
            ("Changed Permissions Since Last Scan", comparison.changed_permissions),
            ("Changed File Hashes Since Last Scan", comparison.changed_hashes),
            ("New Shell History Indicators Since Last Scan", comparison.new_history_indicators),
            ("New Suspicious Files Since Last Scan", comparison.new_suspicious_files),
            ("New Suspicious Processes Since Last Scan", comparison.new_suspicious_processes),
            ("New Suspicious Launch Items Since Last Scan", comparison.new_suspicious_launch_items),
            ("Resolved Findings Since Last Scan", comparison.resolved_findings),
        ]
        high_severity_groups = {
            "New Admin Users Since Last Scan",
            "New Launch Items Since Last Scan",
            "Changed File Hashes Since Last Scan",
            "New Suspicious Files Since Last Scan",
            "New Suspicious Processes Since Last Scan",
            "New Suspicious Launch Items Since Last Scan",
        }
        for group_name, deltas in groups:
            for delta in deltas:
                severity = "high" if group_name in high_severity_groups else "medium"
                findings.append(self._finding(
                    category="Baseline Comparison",
                    title=group_name,
                    severity=severity,
                    description=delta.details,
                    evidence=delta.item_key,
                    evidence_summary=delta.details,
                    raw_evidence_ref=f"baseline:{delta.change_type}:{delta.item_key}",
                    why_this_matters="Changes from the previous scan can highlight recent activity even when a single artifact is ambiguous on its own.",
                    false_positive_notes="Planned software installs, updates, or account changes can create expected deltas.",
                    recommended_next_steps="Validate whether the change matches an approved administrative action or software deployment.",
                    what_can_go_wrong="Reverting a legitimate recent change without validation can disrupt approved software or account management.",
                    command_used="baseline comparison",
                ))
        return findings

    def _finding(self, *, category: str, title: str, severity: str, description: str, evidence: str, evidence_summary: str, raw_evidence_ref: str, why_this_matters: str, false_positive_notes: str, recommended_next_steps: str, what_can_go_wrong: str, command_used: str) -> Finding:
        privilege_context = self._privilege_escalation_context(category, title, description, why_this_matters)
        business_impact = self._business_impact_summary(category, severity, title, description, privilege_context)
        local_network_impact = self._local_network_impact_summary(category, severity, title, description)
        rule = rule_for_finding(category, title, evidence=evidence_summary or evidence, command_used=command_used)
        current_time = utc_now_iso()
        remediation_steps = [step.strip() for step in [recommended_next_steps, "Verify the affected service, file, or account before changing anything.", "Re-run the scan and compare against baseline after any change."] if step.strip()]
        remediation_commands = self._default_remediation_commands(command_used)
        remediation_risk = self._default_remediation_risk(category, recommended_next_steps)
        remediation_references = self._default_remediation_references(category, recommended_next_steps)
        reversible = remediation_risk != "dangerous"
        estimated_impact = "high" if severity in {"critical", "high"} else "medium" if severity == "medium" else "low"
        provenance_text = evidence_summary or evidence
        return Finding(
            id=str(uuid4()),
            category=category,
            title=title,
            severity=severity,  # type: ignore[arg-type]
            description=description,
            evidence=evidence,
            command_used=command_used,
            remediation_suggestion=recommended_next_steps,
            warning=what_can_go_wrong,
            evidence_summary=evidence_summary,
            raw_evidence_ref=raw_evidence_ref,
            why_this_matters=why_this_matters,
            false_positive_notes=false_positive_notes,
            recommended_next_steps=recommended_next_steps,
            what_can_go_wrong=what_can_go_wrong,
            remediation_steps=remediation_steps,
            remediation_commands=remediation_commands,
            remediation_risk=remediation_risk,
            requires_admin="admin" in recommended_next_steps.lower() or "sudo" in command_used.lower(),
            reversible=reversible,
            estimated_impact=estimated_impact,  # type: ignore[arg-type]
            verification_steps=[
                f"Confirm whether the finding title '{title}' still appears in a follow-up scan.",
                f"Validate the affected artifact directly: {evidence_summary}",
            ],
            remediation_references=remediation_references,
            business_impact=business_impact,
            local_network_impact=local_network_impact,
            privilege_escalation_context=privilege_context,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            event_id=f"finding-{title.lower().replace(' ', '-')}-{current_time}",
            event_type="scan_finding",
            trigger_source="scan_collector",
            trigger_subsource=category.lower().replace(" ", "_"),
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=provenance_text,
            normalized_signal=normalized_signal(category, title, provenance_text, command_used),
            evidence_hash=evidence_hash(category, title, provenance_text, command_used),
            related_process=command_used if command_used and not command_used.startswith("/") else "",
            related_path=command_used if command_used.startswith("/") else "",
            first_seen=current_time,
            last_seen=current_time,
            previous_state="not flagged",
            current_state="flagged by scan",
            baseline_status="new observation",
            correlation_id=correlation_id_for(category, title, provenance_text, command_used, timestamp=current_time),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps) + [f"Validate whether the finding still appears in a follow-up scan: {title}"],
            source_trace=f"Detector=scan_collector; Rule={rule.rule_id}; Category={category}; Evidence={provenance_text}",
        )

    def _now_epoch(self) -> float:
        return time.time()

    def _default_remediation_commands(self, command_used: str) -> list[str]:
        normalized = command_used.strip()
        if not normalized:
            return []
        generic_markers = {"scan pipeline", "baseline comparison", "ssh metadata inspection", "local readable sudoers file review", "localhost port scan"}
        if normalized.lower() in generic_markers:
            return []
        if normalized.startswith("/") or " -" in normalized or " " in normalized:
            return [normalized]
        return []

    def _default_remediation_risk(self, category: str, recommended_next_steps: str) -> str:
        combined = f"{category} {recommended_next_steps}".lower()
        if any(term in combined for term in ["delete", "remove", "unload", "sudoers", "daemon", "launchd"]):
            return "dangerous"
        if any(term in combined for term in ["disable", "permission", "chmod", "chown"]):
            return "sensitive"
        return "safe"

    def _default_remediation_references(self, category: str, recommended_next_steps: str) -> list[str]:
        combined = f"{category} {recommended_next_steps}".lower()
        references: list[str] = []
        if "permission" in combined or "authorized key" in combined or "ssh" in combined:
            references.append("Apple Platform Security: Securely extending UNIX authorization and file permissions best practices")
        if "launch" in combined or "daemon" in combined or "service" in combined:
            references.append("Apple Developer Documentation: Creating launchd jobs and property list best practices")
        if "port" in combined or "network" in combined or "proxy" in combined or "firewall" in combined:
            references.append("Apple Platform Security: Network security and service exposure hardening guidance")
        if "sudo" in combined or "admin" in combined or "account" in combined:
            references.append("CIS Apple macOS Benchmark: Account, privilege, and sudo configuration recommendations")
        return references

    def _privilege_escalation_context(self, category: str, title: str, description: str, why_this_matters: str) -> str:
        combined = f"{category} {title} {description} {why_this_matters}".lower()
        markers = [
            "privilege",
            "sudo",
            "admin",
            "hidden user",
            "authorized keys",
            "launchagent",
            "launchdaemon",
            "writable",
            "permission",
            "sip disabled",
            "gatekeeper disabled",
            "filevault disabled",
        ]
        if not any(marker in combined for marker in markers):
            return ""
        return (
            "Privilege escalation means a user, process, or attacker gains more access than intended, "
            "such as moving from a standard user into admin or root control. On a Mac, that can turn a "
            "single local foothold into broad access to credentials, security settings, persistence, or business data."
        )

    def _business_impact_summary(self, category: str, severity: str, title: str, description: str, privilege_context: str) -> str:
        combined = f"{category} {title} {description}".lower()
        if privilege_context:
            return (
                "If abused, this could let someone change security settings, access sensitive files, install persistence, "
                "or move from a normal account into privileged control of the Mac. That can affect business data, trust in the host, and response cost."
            )
        if any(term in combined for term in ["network", "port", "proxy", "firewall", "ssh"]):
            return (
                "This can expand the host's attack surface, expose developer or management services, and increase the chance of unauthorized access to local business data or workflows."
            )
        if severity in {"critical", "high"}:
            return "High-severity findings can affect confidentiality, integrity, or availability of business data and should be reviewed promptly."
        return "Review this finding against the system's intended use, data sensitivity, and support requirements."

    def _local_network_impact_summary(self, category: str, severity: str, title: str, description: str) -> str:
        combined = f"{category} {title} {description}".lower()
        if any(term in combined for term in ["network", "port", "proxy", "ssh", "firewall", "localhost"]):
            return (
                "If the affected service binds beyond localhost or is later reconfigured to do so, nearby systems and shared network segments may be exposed. "
                "Even localhost-only services can increase risk if a local compromise occurs first."
            )
        if any(term in combined for term in ["sudo", "admin", "permission", "launch", "privilege", "writable"]):
            return (
                "This is primarily a local host risk, but successful local privilege escalation can make it easier to tamper with VPN clients, proxies, shared credentials, or services that interact with the local network."
            )
        if severity in {"critical", "high"}:
            return "This finding is centered on the local Mac. Review whether the affected software also exposes shared folders, developer services, or remote administration paths."
        return "Local-network impact appears limited unless the related software also exposes remote services or shared resources."

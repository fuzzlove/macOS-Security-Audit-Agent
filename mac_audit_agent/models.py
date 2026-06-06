from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


RiskLevel = Literal["safe", "sensitive", "dangerous"]
Severity = Literal["info", "low", "medium", "high", "critical"]
SnapshotKind = Literal["ports", "users", "history", "permissions", "files", "processes", "launch_items"]
ImpactLevel = Literal["low", "medium", "high"]
ConfidenceLevel = Literal["low", "medium", "high"]
DiscoveryConfidence = Literal["low", "medium", "high"]
InvestigationNoteStatus = Literal["open", "reviewed", "follow_up", "resolved"]
InvestigationPriority = Literal["low", "medium", "high"]
ReviewState = Literal["not reviewed", "reviewed", "needs follow-up", "false positive", "confirmed concern"]
MonitorEventType = Literal[
    "camera_activity_suspected",
    "camera_activity_confirmed",
    "camera_activity_stopped",
    "microphone_activity_suspected",
    "capture_capable_process_observed",
    "capture_capable_process_closed",
    "capture_process_observed",
    "suspicious_process_observed",
    "screen_wake",
    "screen_sleep",
    "display_sleep",
    "display_wake",
    "display_state_changed",
    "system_wake",
    "system_sleep",
    "screen_locked",
    "screen_unlocked",
    "session_locked",
    "session_unlocked",
    "clamshell_state_changed",
    "possible_lid_closed",
    "possible_lid_opened",
    "lid_closed",
    "lid_opened",
    "screen_sharing_enabled",
    "screen_sharing_disabled",
    "remote_login_enabled",
    "remote_login_disabled",
    "file_sharing_enabled",
    "file_sharing_disabled",
    "screen_recording_permission_present",
    "suspicious_capture_process",
    "persistence_item_created",
    "persistence_item_created_high_risk",
    "launchagent_added",
    "launchdaemon_added",
    "localhost_hidden_port_detected",
    "new_admin_user_detected",
    "protected_monitor_tamper_detected",
    "packet_capture_started",
    "packet_capture_completed",
    "usb_device_connected",
    "bluetooth_device_connected",
    "system_moisture_detected",
    "network_ip_assigned",
    "new_network_connection_detected",
    "network_interface_connected",
    "network_interface_disconnected",
    "new_outbound_connection_detected",
    "new_inbound_connection_detected",
    "new_gateway_detected",
    "new_dns_server_detected",
    "vpn_disconnected",
    "vpn_connected",
    "launchagent_removed",
    "launchdaemon_removed",
    "login_item_added",
    "admin_user_removed",
    "remote_login_enabled",
    "screen_sharing_enabled",
    "monitor_blindness_detected",
    "detector_stopped",
    "heartbeat_stale",
    "db_not_updating",
    "notifier_not_running",
    "unexpected_process_execution",
    "execution_evidence_detected",
    "mitre_persistence_method_detected",
    "possible_shellcode_memory_detected",
    "unsigned_process_from_temp",
    "temp_process_with_network_connection",
    "browser_spawned_shell",
    "mail_spawned_shell",
    "preview_spawned_shell",
    "office_app_spawned_shell",
    "low_trust_binary_executed",
    "port_open_no_process_owner",
    "new_listener_detected",
    "reverse_shell_pattern_detected",
    "persistence_after_execution",
    "admin_change_after_execution",
    "major_security_event",
    "alert_storm_detected",
    "monitor_self_impact_warning",
    "input_activity_idle_started",
    "monitor_self_test",
    "monitor_test_event",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_stdout(result) -> str:
    if isinstance(result, dict):
        return result.get("stdout") or result.get("output") or ""
    return getattr(result, "stdout", "") or getattr(result, "output", "") or ""


def get_stderr(result) -> str:
    if isinstance(result, dict):
        return result.get("stderr") or ""
    return getattr(result, "stderr", "") or ""


def get_exit_code(result):
    if isinstance(result, dict):
        return result.get("exit_code")
    return getattr(result, "exit_code", None)


@dataclass(frozen=True)
class AuditCommand:
    id: str
    name: str
    description: str
    command: list[str]
    privilege_required: bool
    risk_level: RiskLevel
    mutates_system: bool
    timeout_seconds: int
    collection_warning: str
    failure_modes: list[str]
    user_disclaimer: str
    safer_alternative: str
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def preview(self) -> str:
        return " ".join(self.command)


@dataclass
class CommandExecutionResult:
    command_id: str
    command_preview: str
    executed_at: str
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: Severity
    description: str
    evidence: str
    command_used: str
    remediation_suggestion: str
    warning: str
    redacted: bool = False
    command_or_source: str = ""
    needs_admin_for_followup: bool = False
    evidence_summary: str = ""
    raw_evidence_ref: str = ""
    why_this_matters: str = ""
    false_positive_notes: str = ""
    recommended_next_steps: str = ""
    what_can_go_wrong: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    remediation_commands: list[str] = field(default_factory=list)
    remediation_risk: RiskLevel = "safe"
    requires_admin: bool = False
    reversible: bool = True
    estimated_impact: ImpactLevel = "low"
    verification_steps: list[str] = field(default_factory=list)
    remediation_references: list[str] = field(default_factory=list)
    detected_product: str = ""
    detected_version: str = ""
    affected_versions: str = ""
    cve_ids: list[str] = field(default_factory=list)
    kev: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    cvss_score: float | None = None
    confidence: ConfidenceLevel = "medium"
    references: list[str] = field(default_factory=list)
    business_impact: str = ""
    local_network_impact: str = ""
    privilege_escalation_context: str = ""
    rule_id: str = ""
    rule_name: str = ""
    event_id: str = ""
    event_type: str = ""
    trigger_source: str = ""
    trigger_subsource: str = ""
    trigger_rule_id: str = ""
    trigger_rule_name: str = ""
    raw_signal_summary: str = ""
    normalized_signal: str = ""
    evidence_hash: str = ""
    related_process: str = ""
    related_pid: int | None = None
    related_parent_pid: int | None = None
    related_path: str = ""
    related_user: str = ""
    related_network_endpoint: str = ""
    related_url: str = ""
    related_dom_selector: str = ""
    related_file_hash: str = ""
    first_seen: str = ""
    last_seen: str = ""
    previous_state: str = ""
    current_state: str = ""
    baseline_status: str = ""
    correlation_id: str = ""
    suppression_reason: str = ""
    false_positive_hints: list[str] = field(default_factory=list)
    recommended_verification_steps: list[str] = field(default_factory=list)
    source_trace: str = ""
    created_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        try:
            from mac_audit_agent.rules import rule_for_finding

            if not self.rule_id and self.category and self.title:
                rule = rule_for_finding(self.category, self.title, self.evidence, self.command_used)
                if rule and rule.rule_id:
                    self.rule_id = rule.rule_id
                    self.rule_name = rule.name
                    self.trigger_rule_id = rule.rule_id
                    self.trigger_rule_name = rule.name
                    if not self.trigger_source:
                        self.trigger_source = rule.source_detector
                    if not self.false_positive_hints:
                        self.false_positive_hints = list(rule.false_positive_hints)
                    if not self.recommended_verification_steps:
                        self.recommended_verification_steps = list(rule.verification_steps)
        except Exception:
            pass
        if self.severity in {"high", "critical"} and not self.remediation_steps:
            fallback = self.recommended_next_steps or self.remediation_suggestion or "Review the finding carefully before making changes."
            self.remediation_steps = [fallback]
        if not self.verification_steps:
            self.verification_steps = [f"Re-run the relevant audit steps for: {self.title}"]
        if not self.business_impact:
            self.business_impact = "Review the finding in the context of the affected user, service, and data."
        if not self.local_network_impact:
            self.local_network_impact = "Validate whether this finding can affect only the local host or also nearby systems and shared services."
        if not self.recommended_verification_steps:
            self.recommended_verification_steps = list(self.verification_steps)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data["evidence_summary"]:
            data["evidence_summary"] = self.evidence
        if not data["recommended_next_steps"]:
            data["recommended_next_steps"] = self.remediation_suggestion
        if not data["what_can_go_wrong"]:
            data["what_can_go_wrong"] = self.warning
        if not data["command_or_source"]:
            data["command_or_source"] = self.command_used
        if not data["remediation_steps"]:
            data["remediation_steps"] = [data["recommended_next_steps"]]
        if not data["verification_steps"]:
            data["verification_steps"] = [f"Re-run the relevant audit steps and compare against baseline for: {data['title']}"]
        if not data["recommended_verification_steps"]:
            data["recommended_verification_steps"] = list(data["verification_steps"])
        data["recommendation"] = data["recommended_next_steps"]
        return data


def make_finding(**kwargs) -> Finding:
    if "recommendation" in kwargs and "recommended_next_step" not in kwargs and "recommended_next_steps" not in kwargs:
        kwargs["recommended_next_step"] = kwargs.pop("recommendation")
    if "recommended_next_step" in kwargs and "recommended_next_steps" not in kwargs:
        kwargs["recommended_next_steps"] = kwargs.pop("recommended_next_step")
    if "command" in kwargs and "command_or_source" not in kwargs:
        kwargs["command_or_source"] = kwargs.pop("command")
    if "command_or_source" in kwargs and "command_used" not in kwargs:
        kwargs["command_used"] = kwargs["command_or_source"]
    allowed = set(Finding.__dataclass_fields__.keys())
    clean = {key: value for key, value in kwargs.items() if key in allowed}
    return Finding(**clean)


@dataclass
class ScanSummary:
    scan_id: str
    started_at: str
    completed_at: str
    findings_count: int
    security_score: int | None
    notes: str
    new_items_count: int = 0
    score_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortSnapshot:
    process_name: str
    pid: int | None
    local_address: str
    port: int | None
    protocol: str
    state: str
    user: str = ""
    concern: str = ""
    severity: Severity = "info"
    recommended_next_checks: str = ""
    raw: str = ""

    def key(self) -> tuple[str, int | None, str]:
        return (self.process_name, self.port, self.local_address)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkHostSnapshot:
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    likely_hostname: str = ""
    vendor_guess: str = ""
    vendor: str = ""
    reverse_dns: str = ""
    mdns_name: str = ""
    netbios_name: str = ""
    dhcp_hostname: str = ""
    service_names: list[str] = field(default_factory=list)
    device_type: str = ""
    hostname_source: str = ""
    mac_source: str = ""
    interface: str = ""
    discovery_methods: list[str] = field(default_factory=list)
    gateway: bool = False
    baseline_status: str = ""
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    response_time_ms: float | None = None
    confidence: DiscoveryConfidence = "low"
    notes: str = ""
    note_items: list[str] = field(default_factory=list)
    review_needed: bool = False
    review_flags: list[str] = field(default_factory=list)

    def key(self) -> str:
        return self.ip_address

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkDiscoveryComparison:
    new_devices: list[dict[str, Any]] = field(default_factory=list)
    missing_devices: list[dict[str, Any]] = field(default_factory=list)
    changed_mac_for_same_ip: list[dict[str, Any]] = field(default_factory=list)
    changed_hostname_for_same_mac: list[dict[str, Any]] = field(default_factory=list)
    gateway_changed: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkDiscoveryResult:
    scan_id: str
    timestamp: str
    interface: str
    subnet: str
    gateway: str
    gateway_mac: str
    scope: str
    hosts: list[NetworkHostSnapshot] = field(default_factory=list)
    comparison: NetworkDiscoveryComparison = field(default_factory=NetworkDiscoveryComparison)
    raw_logs: list[RawLogEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "interface": self.interface,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "gateway_ip": self.gateway,
            "gateway_mac": self.gateway_mac,
            "scope": self.scope,
            "hosts": [host.to_dict() for host in self.hosts],
            "devices": [host.to_dict() for host in self.hosts],
            "comparison": self.comparison.to_dict(),
            "raw_logs": [entry.to_dict() for entry in self.raw_logs],
            "errors": list(self.errors),
        }

    @property
    def devices(self) -> list[NetworkHostSnapshot]:
        return self.hosts

    @property
    def gateway_ip(self) -> str:
        return self.gateway


LocalNetworkDiscoveryResult = NetworkDiscoveryResult


@dataclass
class UserSnapshot:
    username: str
    uid: int
    gid: int
    shell: str
    home: str
    hidden: bool = False
    admin: bool = False
    locked: bool = False
    disabled: bool = False
    unusual_uid: bool = False
    unusual_gid: bool = False
    shell_enabled: bool = False
    suspicious_home: bool = False
    groups: list[str] = field(default_factory=list)
    authorized_keys_count: int = 0
    authorized_key_types: list[str] = field(default_factory=list)
    authorized_key_comments: list[str] = field(default_factory=list)
    authorized_keys_mode: str = ""
    sudo_rule_count: int = 0
    sudo_rule_sources: list[str] = field(default_factory=list)

    def key(self) -> str:
        return self.username

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HistoryIndicator:
    source_path: str
    shell_type: str
    pattern_id: str
    match_count: int
    snippet: str
    warning: str
    context_included: bool = False

    def key(self) -> tuple[str, str, str]:
        return (self.source_path, self.shell_type, self.pattern_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PermissionSnapshot:
    path: str
    mode: str
    issue: str
    severity: Severity

    def key(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileIssueSnapshot:
    path: str
    issue_type: str
    modified_at: str
    executable: bool
    world_writable: bool
    hidden: bool
    signed_status: str
    sha256: str = ""
    trust_score: int = 50
    trust_label: str = "review"
    trust_summary: str = ""

    def key(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessSnapshot:
    pid: int | None
    ppid: int | None
    user: str
    command_path: str
    process_name: str
    signed_status: str
    trust_level: Literal["trusted", "review", "untrusted"]
    args: str = ""
    reasons: list[str] = field(default_factory=list)
    trust_score: int = 50
    trust_summary: str = ""

    def key(self) -> tuple[int | None, str]:
        return (self.pid, self.command_path)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LaunchItemSnapshot:
    path: str
    label: str
    program: str
    program_arguments: list[str] = field(default_factory=list)
    run_at_load: bool = False
    keep_alive: bool = False
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)

    def key(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineDelta:
    change_type: str
    item_key: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineComparison:
    new_ports: list[BaselineDelta] = field(default_factory=list)
    new_users: list[BaselineDelta] = field(default_factory=list)
    new_admin_users: list[BaselineDelta] = field(default_factory=list)
    new_launch_items: list[BaselineDelta] = field(default_factory=list)
    changed_permissions: list[BaselineDelta] = field(default_factory=list)
    new_history_indicators: list[BaselineDelta] = field(default_factory=list)
    new_suspicious_files: list[BaselineDelta] = field(default_factory=list)
    new_suspicious_processes: list[BaselineDelta] = field(default_factory=list)
    new_suspicious_launch_items: list[BaselineDelta] = field(default_factory=list)
    removed_users: list[BaselineDelta] = field(default_factory=list)
    removed_ports: list[BaselineDelta] = field(default_factory=list)
    removed_launch_items: list[BaselineDelta] = field(default_factory=list)
    changed_hashes: list[BaselineDelta] = field(default_factory=list)
    resolved_findings: list[BaselineDelta] = field(default_factory=list)
    drift_score: int = 0
    drift_label: str = "stable"
    drift_summary: str = ""
    high_risk_change_count: int = 0

    def total_changes(self) -> int:
        return sum(
            len(group)
            for group in [
                self.new_ports,
                self.new_users,
                self.new_admin_users,
                self.new_launch_items,
                self.changed_permissions,
                self.new_history_indicators,
                self.new_suspicious_files,
                self.new_suspicious_processes,
                self.new_suspicious_launch_items,
                self.removed_users,
                self.removed_ports,
                self.removed_launch_items,
                self.changed_hashes,
                self.resolved_findings,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RawLogEntry:
    collector_name: str
    command_or_source: str
    timestamp: str
    exit_code: int | None
    stderr_summary: str
    stdout_summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanError:
    collector_name: str
    message: str
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectorResult:
    collector_name: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    raw_logs: list[RawLogEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_name": self.collector_name,
            "artifacts": self.artifacts,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "raw_logs": [entry.to_dict() for entry in self.raw_logs],
        }


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    hostname: str
    current_user: str
    findings: list[Finding] = field(default_factory=list)
    raw_logs: list[RawLogEntry] = field(default_factory=list)
    collected_artifacts: dict[str, Any] = field(default_factory=dict)
    baseline_diff: dict[str, Any] = field(default_factory=dict)
    errors: list[ScanError] = field(default_factory=list)

    @property
    def artifacts(self) -> dict[str, Any]:
        return self.collected_artifacts

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "current_user": self.current_user,
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_logs": [entry.to_dict() for entry in self.raw_logs],
            "collected_artifacts": self._serialize(self.collected_artifacts),
            "baseline_diff": self._serialize(self.baseline_diff),
            "errors": [error.to_dict() for error in self.errors],
        }

    def _serialize(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._serialize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._serialize(item) for item in value]
        if isinstance(value, set):
            return sorted(self._serialize(item) for item in value)
        if hasattr(value, "to_dict"):
            return self._serialize(value.to_dict())
        return value


@dataclass
class BackgroundMonitorEvent:
    event_id: str
    timestamp: str
    event_type: MonitorEventType
    severity: Severity
    source: str
    process_name: str = ""
    pid: int | None = None
    evidence: str = ""
    confidence: ConfidenceLevel = "low"
    recommendation: str = ""
    simulated: bool = False
    notification_sent: bool = False
    notification_error: str = ""
    notification_returncode: int | None = None
    notification_decision: str = "log_only"
    notification_reason: str = ""
    cooldown_remaining_seconds: int = 0
    popup_allowed: bool = False
    visible_alert_shown: bool = False
    alert_style: str = "neutral_grey"
    cooldown_suppressed: bool = False
    last_suppression_reason: str = ""
    metadata_json: str = "{}"
    rule_id: str = ""
    rule_name: str = ""
    trigger_source: str = ""
    trigger_subsource: str = ""
    trigger_rule_id: str = ""
    trigger_rule_name: str = ""
    raw_signal_summary: str = ""
    normalized_signal: str = ""
    evidence_hash: str = ""
    related_process: str = ""
    related_pid: int | None = None
    related_parent_pid: int | None = None
    related_path: str = ""
    related_user: str = ""
    related_network_endpoint: str = ""
    related_url: str = ""
    related_dom_selector: str = ""
    related_file_hash: str = ""
    first_seen: str = ""
    last_seen: str = ""
    previous_state: str = ""
    current_state: str = ""
    baseline_status: str = ""
    correlation_id: str = ""
    suppression_reason: str = ""
    false_positive_hints: list[str] = field(default_factory=list)
    recommended_verification_steps: list[str] = field(default_factory=list)
    source_trace: str = ""
    occurrence_count: int = 1
    duplicate_count: int = 0
    duplicate_group_key: str = ""
    duplicate_category: str = "single"

    def __post_init__(self) -> None:
        try:
            from mac_audit_agent.rules import rule_for_event

            if not self.rule_id and self.event_type:
                rule = rule_for_event(str(self.event_type))
                if rule and rule.rule_id and rule.enabled_by_default:
                    self.rule_id = rule.rule_id
                    self.rule_name = rule.name
                    self.trigger_rule_id = rule.rule_id
                    self.trigger_rule_name = rule.name
                    if not self.trigger_source:
                        self.trigger_source = rule.source_detector
                    if not self.false_positive_hints:
                        self.false_positive_hints = list(rule.false_positive_hints)
                    if not self.recommended_verification_steps:
                        self.recommended_verification_steps = list(rule.verification_steps)
        except Exception:
            pass

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EventAlertTrace:
    trace_id: str
    event_id: str
    event_type: str
    original_event_type: str = ""
    normalized_event_type: str = ""
    detector_source: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    stored_db_path: str = ""
    stored_success: bool = False
    notifier_db_path: str = ""
    notifier_poll_seen: bool = False
    notifier_poll_time: str = ""
    notifier_cursor_before: str = ""
    notifier_cursor_after: str = ""
    notifier_seen: bool = False
    notifier_seen_at: str = ""
    notification_policy_checked: bool = False
    notification_policy_result: str = ""
    notification_policy_reason: str = ""
    severity_before_policy: str = ""
    severity_after_policy: str = ""
    cooldown_checked: bool = False
    cooldown_result: str = ""
    alert_required: bool = False
    alert_suppressed: bool = False
    alert_suppression_reason: str = ""
    alert_queue_enqueued: bool = False
    alert_queue_length_before: int = 0
    alert_queue_length_after: int = 0
    overlay_dispatch_attempted: bool = False
    overlay_dispatch_at: str = ""
    overlay_dispatch_result: str = ""
    overlay_error: str = ""
    visible_alert_id: str = ""
    displayed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NotificationCapabilities:
    overlay_available: bool = False
    applescript_dialog_available: bool = False
    notification_center_available: bool = False
    osascript_exists: bool = False
    last_test_time: str = ""
    last_test_result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AlertDeliveryRecord:
    event_id: str
    alert_type: str
    overlay_attempted: bool = False
    overlay_success: bool = False
    dialog_attempted: bool = False
    dialog_success: bool = False
    notification_attempted: bool = False
    notification_success: bool = False
    delivery_method_used: str = ""
    updated_at: str = field(default_factory=utc_now_iso)
    payload_json: str = "{}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BackgroundMonitorStatus:
    installed: bool = False
    loaded: bool = False
    running: bool = False
    enabled: bool = False
    plist_path: str = ""
    label: str = ""
    log_path: str = ""
    db_path: str = ""
    process_pid: int | None = None
    last_heartbeat: str = ""
    last_event_timestamp: str = ""
    last_error: str = ""
    notification_status: str = "unknown"
    current_launchctl_domain: str = ""
    detector_errors: str = ""
    events_last_10_minutes: int = 0
    detector_last_run_timestamp: str = ""
    detector_last_run_counts: str = ""
    detector_enabled_camera: bool = False
    detector_enabled_session: bool = False
    detector_enabled_network: bool = False
    detector_enabled_persistence: bool = False
    detector_enabled_sharing: bool = False
    detector_enabled_process: bool = False
    detector_enabled_hardware: bool = False
    detector_last_zero_reason: str = ""
    status_text: str = ""
    current_snapshot: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationNote:
    note_id: str
    created_at: str
    updated_at: str
    title: str
    body: str
    tags: list[str] = field(default_factory=list)
    linked_finding_id: str = ""
    linked_scan_id: str = ""
    status: InvestigationNoteStatus = "open"
    priority: InvestigationPriority = "medium"
    investigator_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewChecklistItem:
    item_type: str
    item_key: str
    label: str
    review_state: ReviewState = "not reviewed"
    linked_scan_id: str = ""
    linked_finding_id: str = ""
    updated_at: str = field(default_factory=utc_now_iso)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingSuppressionRule:
    fingerprint: str
    title: str
    category: str
    severity: Severity
    review_state: ReviewState
    rationale: str
    active: bool = True
    matched_count: int = 0
    first_seen_at: str = field(default_factory=utc_now_iso)
    last_seen_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationAuditEntry:
    audit_id: int | None
    timestamp: str
    action_type: str
    entity_type: str
    entity_id: str
    previous_status: str = ""
    new_status: str = ""
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

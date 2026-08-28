from __future__ import annotations

import ctypes
import ctypes.util
import json
import platform
import sqlite3
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.process_explorer import collect_process_snapshot
from mac_audit_agent.keylogger_threat_knowledge import ATTACK_TECHNIQUES,knowledge_summary,match_documented_behavior


KEY_DOWN_MASK = 1 << 10
KEY_UP_MASK = 1 << 11
TCC_KEYBOARD_SERVICES = {"kTCCServiceListenEvent", "kTCCServiceAccessibility"}
USER_WRITABLE_MARKERS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/", "/Downloads/")
PERCENTAGE_BASIS = (
    "Heuristic evidence rubric; percentages are analytic estimates, not a measured product accuracy rate. "
    "Measured accuracy requires adjudicated true-positive and false-positive outcomes."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EventTap:
    tap_id: int
    source_pid: int
    target_pid: int
    events_of_interest: int
    enabled: bool
    listen_only: bool
    source_path: str = ""

    @property
    def keyboard_interested(self) -> bool:
        return bool(self.events_of_interest & (KEY_DOWN_MASK | KEY_UP_MASK))

    @property
    def global_scope(self) -> bool:
        return self.target_pid == 0


@dataclass
class KeyloggerFinding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    score: int
    process_name: str = ""
    pid: int | None = None
    path: str = ""
    bundle_id: str = ""
    signals: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    classification: str = "needs_review"
    attack_techniques: list[dict[str, Any]] = field(default_factory=list)
    documented_threat_context: list[dict[str, Any]] = field(default_factory=list)
    analytic_confidence_percent: int = 0
    false_positive_risk_percent: int = 100
    percentage_basis: str = PERCENTAGE_BASIS
    intervention_actions: list[str] = field(default_factory=list)
    removal_actions: list[str] = field(default_factory=list)
    remediation_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class KeyloggerScanReport:
    started_at: str
    completed_at: str
    findings: list[KeyloggerFinding]
    event_tap_count: int
    tcc_grant_count: int
    coverage: dict[str, str]
    warnings: list[str] = field(default_factory=list)
    threat_knowledge: dict[str, Any] = field(default_factory=dict)
    accuracy_rate_percent: float | None = None
    accuracy_basis: str = "not_measured_no_adjudicated_outcomes"

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "findings": [finding.to_dict() for finding in self.findings],
        }


class _CGEventTapInformation(ctypes.Structure):
    _fields_ = [
        ("eventTapID", ctypes.c_uint32),
        ("tapPoint", ctypes.c_uint32),
        ("options", ctypes.c_uint32),
        ("eventsOfInterest", ctypes.c_uint64),
        ("tappingProcess", ctypes.c_int32),
        ("processBeingTapped", ctypes.c_int32),
        ("enabled", ctypes.c_bool),
        ("minUsecLatency", ctypes.c_double),
        ("avgUsecLatency", ctypes.c_double),
        ("maxUsecLatency", ctypes.c_double),
    ]


def enumerate_event_taps() -> tuple[list[EventTap], str]:
    if platform.system() != "Darwin":
        return [], "unsupported: event taps are a macOS capability"
    framework = ctypes.util.find_library("ApplicationServices")
    if not framework:
        return [], "unavailable: ApplicationServices framework not found"
    try:
        api = ctypes.CDLL(framework)
        function = api.CGGetEventTapList
        function.argtypes = [ctypes.c_uint32, ctypes.POINTER(_CGEventTapInformation), ctypes.POINTER(ctypes.c_uint32)]
        function.restype = ctypes.c_int32
        count = ctypes.c_uint32(0)
        if function(0, None, ctypes.byref(count)) != 0:
            return [], "unavailable: CGGetEventTapList denied or failed"
        if count.value == 0:
            return [], "available"
        buffer = (_CGEventTapInformation * count.value)()
        if function(count.value, buffer, ctypes.byref(count)) != 0:
            return [], "unavailable: event tap enumeration failed"
        taps = [
            EventTap(
                tap_id=int(item.eventTapID),
                source_pid=int(item.tappingProcess),
                target_pid=int(item.processBeingTapped),
                events_of_interest=int(item.eventsOfInterest),
                enabled=bool(item.enabled),
                listen_only=int(item.options) == 1,
            )
            for item in buffer[: count.value]
        ]
        return taps, "available"
    except (AttributeError, OSError, ValueError) as exc:
        return [], f"unavailable: {exc}"


def _processes() -> dict[int, dict[str, str]]:
    records, _status = collect_process_snapshot()
    return {record.pid: {"path": record.path, "args": " ".join(record.arguments)} for record in records}


def _tcc_rows() -> tuple[list[dict[str, Any]], str]:
    paths = [
        Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    ]
    rows: list[dict[str, Any]] = []
    readable = 0
    for path in paths:
        if not path.exists():
            continue
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(access)")}
            auth_column = "auth_value" if "auth_value" in columns else "allowed"
            query = f"SELECT service, client, client_type, {auth_column} AS auth_value FROM access WHERE service IN (?, ?)"
            for row in connection.execute(query, tuple(sorted(TCC_KEYBOARD_SERVICES))):
                payload = dict(row)
                if int(payload.get("auth_value", 0) or 0) > 0:
                    payload["database"] = "user" if str(path).startswith(str(Path.home())) else "system"
                    rows.append(payload)
            connection.close()
            readable += 1
        except (OSError, sqlite3.Error):
            continue
    status = "available" if readable else "restricted: grant Full Disk Access for complete TCC coverage"
    return rows, status


def _signature(path: str) -> dict[str, Any]:
    if not path or not Path(path).exists():
        return {"valid": False, "authority": "", "team_id": "", "status": "path unavailable"}
    try:
        verify = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", path], capture_output=True, text=True, timeout=10)
        detail = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=4", path], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"valid": False, "authority": "", "team_id": "", "status": str(exc)}
    text = detail.stderr
    team_id = next((line.split("=", 1)[1] for line in text.splitlines() if line.startswith("TeamIdentifier=")), "")
    authority = next((line.split("=", 1)[1] for line in text.splitlines() if line.startswith("Authority=")), "")
    return {"valid": verify.returncode == 0, "authority": authority, "team_id": team_id, "status": verify.stderr.strip()}


class KeyloggerScanner:
    def __init__(
        self,
        *,
        tap_provider: Callable[[], tuple[list[EventTap], str]] = enumerate_event_taps,
        process_provider: Callable[[], dict[int, dict[str, str]]] = _processes,
        tcc_provider: Callable[[], tuple[list[dict[str, Any]], str]] = _tcc_rows,
        signature_provider: Callable[[str], dict[str, Any]] = _signature,
    ) -> None:
        self.tap_provider = tap_provider
        self.process_provider = process_provider
        self.tcc_provider = tcc_provider
        self.signature_provider = signature_provider

    def scan(self) -> KeyloggerScanReport:
        started = _now()
        taps, tap_status = self.tap_provider()
        processes = self.process_provider()
        grants, tcc_status = self.tcc_provider()
        findings: list[KeyloggerFinding] = []
        keyboard_taps = [tap for tap in taps if tap.enabled and tap.keyboard_interested]
        for tap in keyboard_taps:
            process = processes.get(tap.source_pid, {})
            path = tap.source_path or str(process.get("path", ""))
            signature = self.signature_provider(path)
            signals = ["enabled keyboard event tap"]
            score = 35
            behavior_signals,threat_matches=match_documented_behavior(path,str(process.get("args","")))
            signals.extend(behavior_signals); score += 15*bool(behavior_signals)+20*bool(threat_matches)
            if tap.global_scope:
                signals.append("system-wide event tap")
                score += 20
            if not tap.listen_only:
                signals.append("active filtering tap")
                score += 10
            if any(marker in path for marker in USER_WRITABLE_MARKERS):
                signals.append("executable in a temporary or broadly writable location")
                score += 25
            if not signature.get("valid"):
                signals.append("missing or invalid code signature")
                score += 20
            severity = "critical" if score >= 80 else "high" if score >= 55 else "medium"
            bounded_score = min(score, 100)
            confidence_percent = min(98, 55 + round(bounded_score * 0.4))
            false_positive_percent = max(5, 100 - bounded_score)
            findings.append(
                KeyloggerFinding(
                    finding_id=f"event-tap-{tap.tap_id}-{tap.source_pid}",
                    title="Process can intercept keyboard events",
                    severity=severity,
                    confidence="high",
                    score=bounded_score,
                    process_name=Path(path).name if path else f"PID {tap.source_pid}",
                    pid=tap.source_pid,
                    path=path,
                    signals=signals,
                    evidence={"tap": asdict(tap), "signature": signature, "arguments": process.get("args", "")},
                    recommendation="Verify the application and publisher. Revoke Input Monitoring or Accessibility access if unexpected, then investigate its persistence and network activity.",
                    classification="suspicious_capability",
                    attack_techniques=[dict(ATTACK_TECHNIQUES[0])],
                    documented_threat_context=threat_matches,
                    analytic_confidence_percent=confidence_percent,
                    false_positive_risk_percent=false_positive_percent,
                    intervention_actions=[
                        "Preserve evidence and confirm the process owner, publisher, and business need.",
                        "If risk is imminent, revalidate the PID and executable before suspending or stopping it.",
                    ],
                    removal_actions=[
                        "Quarantine the exact executable and discovered persistence only after analyst validation.",
                        "Use reversible unhook and quarantine when the event-tap owner is verified.",
                    ],
                    remediation_actions=[
                        "Review Input Monitoring and Accessibility access in System Settings.",
                        "Rescan, verify that the event tap is gone, and review credentials if capture is suspected.",
                    ],
                )
            )
        tapped_paths = {finding.path for finding in findings if finding.path}
        for grant in grants:
            client = str(grant.get("client", ""))
            if client in tapped_paths:
                continue
            service = str(grant.get("service", ""))
            permission_score = 35 if service == "kTCCServiceListenEvent" else 25
            findings.append(
                KeyloggerFinding(
                    finding_id=f"tcc-{service}-{client}",
                    title="Application has keyboard-observation permission",
                    severity="medium",
                    confidence="medium",
                    score=permission_score,
                    process_name=Path(client).name if client.startswith("/") else client,
                    path=client if client.startswith("/") else "",
                    bundle_id="" if client.startswith("/") else client,
                    signals=["Input Monitoring grant" if service == "kTCCServiceListenEvent" else "Accessibility grant"],
                    evidence=grant,
                    recommendation="Confirm this permission is needed. A permission grant alone does not prove keylogging; correlate it with event taps, signing, persistence, and behavior.",
                    classification="permission_exposure",
                    attack_techniques=[{**dict(ATTACK_TECHNIQUES[0]),"relationship":"exposure_only","observed":False}],
                    analytic_confidence_percent=60,
                    false_positive_risk_percent=85 if service == "kTCCServiceAccessibility" else 75,
                    intervention_actions=[
                        "Confirm the permission grant is expected and belongs to an approved application.",
                        "Investigate event taps, persistence, signing, and behavior before containment.",
                    ],
                    removal_actions=["Removal is not recommended from a permission grant alone."],
                    remediation_actions=[
                        "Revoke unneeded Input Monitoring or Accessibility access through System Settings.",
                        "Rescan after the permission review and document the authorized business need.",
                    ],
                )
            )
        findings.sort(key=lambda item: (-item.score, item.process_name.lower()))
        warnings = []
        if not tap_status.startswith("available"):
            warnings.append(tap_status)
        if not tcc_status.startswith("available"):
            warnings.append(tcc_status)
        return KeyloggerScanReport(started, _now(), findings, len(keyboard_taps), len(grants), {"event_taps": tap_status, "tcc": tcc_status, "signing": "available"}, warnings, knowledge_summary())


def report_json(report: KeyloggerScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)

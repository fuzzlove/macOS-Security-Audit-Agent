from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_event


CAPTURE_PROCESS_KEYWORDS = [
    "Photo Booth",
    "Photo Booth.app",
    "FaceTime",
    "Zoom",
    "zoom.us",
    "Microsoft Teams",
    "Teams",
    "Webex",
    "Discord",
    "Google Chrome",
    "Safari",
    "Firefox",
    "QuickTime Player",
    "OBS",
    "Camo Studio",
]
MICROPHONE_PROCESS_KEYWORDS = [
    "FaceTime",
    "Zoom",
    "zoom.us",
    "Microsoft Teams",
    "Teams",
    "Webex",
    "Discord",
    "Google Chrome",
    "Safari",
    "Firefox",
    "QuickTime Player",
    "OBS",
    "Camo Studio",
]
SUSPICIOUS_CAPTURE_KEYWORDS = CAPTURE_PROCESS_KEYWORDS + [
    "screensharingd",
    "Screen Sharing",
    "ARDAgent",
    "screencapture",
]
CAMERA_HELPER_KEYWORDS = [
    "VDCAssistant",
    "AppleCameraAssistant",
    "CMIOGraph",
    "CMIOExtensionProvider",
]
PS_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*?)\s{2,}(.*)$")


@dataclass
class PrivacyMonitorSnapshot:
    camera_authorization: str = "unknown"
    microphone_authorization: str = "unknown"
    camera_active_api: bool = False
    capture_capable_processes: list[dict] = field(default_factory=list)
    camera_helper_processes: list[dict] = field(default_factory=list)
    microphone_processes: list[dict] = field(default_factory=list)
    suspicious_capture_processes: list[dict] = field(default_factory=list)
    screen_sharing_enabled: bool = False
    screen_recording_permissions: list[dict] = field(default_factory=list)
    camera_permissions: list[dict] = field(default_factory=list)
    microphone_permissions: list[dict] = field(default_factory=list)
    unified_log_indicators: list[dict] = field(default_factory=list)
    raw_ps_lines: list[str] = field(default_factory=list)


def run_command(command: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


class PrivacyMonitor:
    def __init__(self, executor=run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> PrivacyMonitorSnapshot:
        processes, raw_ps_lines = self._list_processes()
        capture_capable = [item for item in processes if self._matches_process(item, CAPTURE_PROCESS_KEYWORDS)]
        camera_helpers = [item for item in processes if self._matches_process(item, CAMERA_HELPER_KEYWORDS)]
        microphones = [item for item in processes if self._matches_process(item, MICROPHONE_PROCESS_KEYWORDS)]
        suspicious = [item for item in processes if self._matches_process(item, SUSPICIOUS_CAPTURE_KEYWORDS)]
        return PrivacyMonitorSnapshot(
            camera_authorization=self._camera_authorization_status(),
            microphone_authorization=self._microphone_authorization_status(),
            camera_active_api=self._camera_active_via_avfoundation(),
            capture_capable_processes=capture_capable,
            camera_helper_processes=camera_helpers,
            microphone_processes=microphones,
            suspicious_capture_processes=suspicious,
            screen_sharing_enabled=self._screen_sharing_enabled(),
            screen_recording_permissions=self._screen_recording_permissions(),
            camera_permissions=self._tcc_permissions("kTCCServiceCamera"),
            microphone_permissions=self._tcc_permissions("kTCCServiceMicrophone"),
            unified_log_indicators=self._unified_log_indicators(),
            raw_ps_lines=raw_ps_lines,
        )

    def evaluate(self, previous: PrivacyMonitorSnapshot | None, current: PrivacyMonitorSnapshot) -> list[BackgroundMonitorEvent]:
        timestamp = utc_now_iso()
        events: list[BackgroundMonitorEvent] = []

        previous_capture = {self._process_key(item): item for item in (previous.capture_capable_processes if previous else [])}
        current_capture = {self._process_key(item): item for item in current.capture_capable_processes}
        for key, item in current_capture.items():
            if key in previous_capture:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="capture_capable_process_observed",
                    severity="medium",
                    source="process_poll",
                    process_name=str(item.get("name", "")),
                    pid=item.get("pid"),
                    evidence=(
                        f"Capture-capable process observed: {item.get('name', 'unknown')} "
                        f"(pid={item.get('pid', 'unknown')}, args={item.get('redacted_args', '')})"
                    ),
                    confidence="low",
                    recommendation="Review whether the app was expected to be open and capable of capture.",
                    metadata=item,
                    rule=rule_for_event("capture_capable_process_observed"),
                    previous_state="not observed",
                    current_state=str(item.get("name", "")),
                )
            )
        for key, item in previous_capture.items():
            if key in current_capture:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="capture_capable_process_closed",
                    severity="info",
                    source="process_poll",
                    process_name=str(item.get("name", "")),
                    pid=item.get("pid"),
                    evidence=f"Capture-capable process closed: {item.get('name', 'unknown')} (pid={item.get('pid', 'unknown')}).",
                    confidence="low",
                    recommendation="Correlate the closure with expected user activity.",
                    metadata=item,
                    rule=rule_for_event("capture_capable_process_closed"),
                    previous_state=str(item.get("name", "")),
                    current_state="closed",
                )
            )

        if current.camera_active_api and not (previous and previous.camera_active_api):
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="camera_activity_confirmed",
                    severity="high",
                    source="AVFoundation",
                    evidence="Public AVFoundation APIs reported an in-use or active camera indication.",
                    confidence="high",
                    recommendation="Confirm whether camera use is expected and close the app if it is not.",
                    metadata={"authorization": current.camera_authorization},
                    rule=rule_for_event("camera_activity_confirmed"),
                    previous_state="camera inactive",
                    current_state="camera active signal present",
                )
            )
        elif previous and previous.camera_active_api and not current.camera_active_api:
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="camera_activity_stopped",
                    severity="info",
                    source="AVFoundation",
                    evidence="Public AVFoundation APIs no longer report an active camera indication.",
                    confidence="high",
                    recommendation="Correlate the camera stop transition with the expected application lifecycle.",
                    metadata={"authorization": current.camera_authorization},
                    rule=rule_for_event("camera_activity_stopped"),
                    previous_state="camera active signal present",
                    current_state="camera inactive",
                )
            )
        else:
            previous_helpers = {self._process_key(item): item for item in (previous.camera_helper_processes if previous else [])}
            current_helpers = {self._process_key(item): item for item in current.camera_helper_processes}
            for key, item in current_helpers.items():
                if key in previous_helpers:
                    continue
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type="camera_activity_suspected",
                        severity="medium",
                        source="camera_helper_process",
                        process_name=str(item.get("name", "")),
                        pid=item.get("pid"),
                        evidence=f"Camera helper process observed: {item.get('name', 'unknown')}",
                        confidence="medium",
                        recommendation="Confirm whether camera use is expected and close the related app if it is not.",
                        metadata=item,
                        rule=rule_for_event("camera_activity_suspected"),
                        previous_state="helper not observed",
                        current_state=str(item.get("name", "")),
                    )
                )
            previous_had_correlation = bool(previous and previous.capture_capable_processes and previous.camera_helper_processes)
            if current.capture_capable_processes and current.camera_helper_processes and not previous_had_correlation:
                app_names = ", ".join(sorted({str(item.get("name", "")) for item in current.capture_capable_processes if item.get("name")}))
                helper_names = ", ".join(sorted({str(item.get("name", "")) for item in current.camera_helper_processes if item.get("name")}))
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type="camera_activity_suspected",
                        severity="medium",
                        source="process_correlation",
                        evidence=f"Capture-capable app and camera helper observed together: apps={app_names}; helpers={helper_names}",
                        confidence="medium",
                        recommendation="Confirm whether camera use is expected and close the related app if it is not.",
                        metadata={"apps": current.capture_capable_processes, "helpers": current.camera_helper_processes},
                        rule=rule_for_event("camera_activity_suspected"),
                        previous_state="apps/helpers not correlated",
                        current_state=f"apps={app_names}; helpers={helper_names}",
                    )
                )

        previous_microphones = {self._process_key(item): item for item in (previous.microphone_processes if previous else [])}
        current_microphones = {self._process_key(item): item for item in current.microphone_processes}
        for key, item in current_microphones.items():
            if key in previous_microphones:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="microphone_activity_suspected",
                    severity="medium",
                    source="process_poll",
                    process_name=str(item.get("name", "")),
                    pid=item.get("pid"),
                    evidence=f"Capture-capable process observed: {item.get('name', 'unknown')}",
                    confidence="low",
                    recommendation="Check whether the listed app is expected to use the microphone right now.",
                    metadata=item,
                    rule=rule_for_event("microphone_activity_suspected"),
                    previous_state="not observed",
                    current_state=str(item.get("name", "")),
                )
            )

        previous_permissions = {item.get("client") for item in (previous.screen_recording_permissions if previous else [])}
        for item in current.screen_recording_permissions:
            if item.get("client") in previous_permissions:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="screen_recording_permission_present",
                    severity="medium",
                    source="TCC",
                    process_name=str(item.get("client", "")),
                    evidence=f"Screen Recording permission posture present for {item.get('client', 'unknown app')}.",
                    confidence="high",
                    recommendation="Review whether the app should retain Screen Recording permission.",
                    metadata=item,
                    rule=rule_for_event("screen_recording_permission_present"),
                    previous_state="permission absent",
                    current_state=str(item.get("client", "")),
                )
            )

        previous_camera_permissions = {item.get("client") for item in (previous.camera_permissions if previous else [])}
        for item in current.camera_permissions:
            if item.get("client") in previous_camera_permissions:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="camera_activity_suspected",
                    severity="info",
                    source="TCC",
                    process_name=str(item.get("client", "")),
                    evidence=f"Camera permission posture present for {item.get('client', 'unknown app')}.",
                    confidence="medium",
                    recommendation="Review whether the app should retain Camera permission.",
                    metadata=item,
                    rule=rule_for_event("camera_activity_suspected"),
                    previous_state="permission absent",
                    current_state=str(item.get("client", "")),
                )
            )

        previous_microphone_permissions = {item.get("client") for item in (previous.microphone_permissions if previous else [])}
        for item in current.microphone_permissions:
            if item.get("client") in previous_microphone_permissions:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="microphone_activity_suspected",
                    severity="info",
                    source="TCC",
                    process_name=str(item.get("client", "")),
                    evidence=f"Microphone permission posture present for {item.get('client', 'unknown app')}.",
                    confidence="medium",
                    recommendation="Review whether the app should retain Microphone permission.",
                    metadata=item,
                    rule=rule_for_event("microphone_activity_suspected"),
                    previous_state="permission absent",
                    current_state=str(item.get("client", "")),
                )
            )

        previous_suspicious = {self._process_key(item): item for item in (previous.suspicious_capture_processes if previous else [])}
        current_suspicious = {self._process_key(item): item for item in current.suspicious_capture_processes}
        for key, item in current_suspicious.items():
            if key in previous_suspicious:
                continue
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="capture_process_observed",
                    severity="medium",
                    source="process_poll",
                    process_name=str(item.get("name", "")),
                    pid=item.get("pid"),
                    evidence=f"Capture- or screen-sharing-associated process observed: {item.get('name', 'unknown')}",
                    confidence="medium",
                    recommendation="Validate whether this process is expected before ending it or changing permissions.",
                    metadata=item,
                )
            )

        for item in current.unified_log_indicators:
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type=str(item.get("event_type", "capture_process_observed")),
                    severity=str(item.get("severity", "info")),
                    source="unified_log",
                    process_name=str(item.get("process_name", "")),
                    pid=item.get("pid"),
                    evidence=str(item.get("evidence", "Unified log indicator observed.")),
                    confidence=str(item.get("confidence", "low")),
                    recommendation="Review whether the observed privacy-related activity was expected.",
                    metadata=item,
                )
            )
        return events

    def initial_capture_process_events(self, current: PrivacyMonitorSnapshot) -> list[BackgroundMonitorEvent]:
        timestamp = utc_now_iso()
        events: list[BackgroundMonitorEvent] = []
        for item in current.capture_capable_processes:
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="capture_capable_process_observed",
                    severity="medium",
                    source="process_poll",
                    process_name=str(item.get("name", "")),
                    pid=item.get("pid"),
                    evidence=(
                        f"Capture-capable process observed: {item.get('name', 'unknown')} "
                        f"(pid={item.get('pid', 'unknown')}, args={item.get('redacted_args', '')})"
                    ),
                    confidence="low",
                    recommendation="Review whether the app was expected to be open and capable of capture.",
                    metadata=item,
                )
            )
        return events

    def current_capture_processes(self, snapshot: PrivacyMonitorSnapshot) -> list[dict]:
        return list(snapshot.capture_capable_processes)

    def _event(
        self,
        *,
        timestamp: str,
        event_type: str,
        severity: str,
        source: str,
        evidence: str,
        confidence: str,
        recommendation: str,
        process_name: str = "",
        pid: int | None = None,
        metadata: dict,
        rule=None,
        previous_state: str = "",
        current_state: str = "",
    ) -> BackgroundMonitorEvent:
        rule = rule or rule_for_event(event_type)
        raw_summary = evidence
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{process_name or source}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source=source,
            process_name=process_name,
            pid=pid,
            evidence=evidence,
            confidence=confidence,
            recommendation=recommendation,
            metadata_json=json.dumps(self._sanitize_metadata(metadata), sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="privacy_monitor",
            trigger_subsource=source,
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=raw_summary,
            normalized_signal=normalized_signal(event_type, raw_summary, process_name, metadata),
            evidence_hash=evidence_hash(event_type, raw_summary, process_name, metadata),
            related_process=process_name,
            related_pid=pid,
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state=previous_state,
            current_state=current_state,
            baseline_status="privacy state change",
            correlation_id=correlation_id_for(event_type, source, process_name, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Evidence={raw_summary}",
        )

    def _sanitize_metadata(self, metadata: dict) -> dict:
        cleaned = dict(metadata)
        for forbidden in ("image", "frame", "audio", "keystroke", "content", "packet"):
            cleaned.pop(forbidden, None)
        return cleaned

    def _process_key(self, process: dict) -> tuple[int | None, str, str]:
        return (process.get("pid"), str(process.get("name", "")), str(process.get("redacted_args", "")))

    def _list_processes(self) -> tuple[list[dict], list[str]]:
        code, stdout, _stderr = self.executor(["/bin/ps", "-axo", "pid=,comm=,args="])
        if code != 0:
            return [], []
        processes: list[dict] = []
        raw_ps_lines: list[str] = []
        for line in stdout.splitlines():
            raw = line.rstrip()
            if not raw.strip():
                continue
            raw_ps_lines.append(raw)
            match = PS_LINE_RE.match(raw)
            if match:
                pid = int(match.group(1))
                command = match.group(2).strip()
                args = match.group(3).strip()
            else:
                parts = raw.strip().split(maxsplit=2)
                if len(parts) < 2:
                    continue
                try:
                    pid = int(parts[0])
                except ValueError:
                    continue
                command = parts[1]
                args = parts[2] if len(parts) > 2 else ""
            processes.append(
                {
                    "pid": pid,
                    "name": Path(command).name,
                    "command": command,
                    "args": args,
                    "redacted_args": self._redact_args(args),
                }
            )
        return processes, raw_ps_lines

    def _redact_args(self, args: str) -> str:
        redacted = args.replace(str(Path.home()), "~")
        if len(redacted) > 220:
            return redacted[:217] + "..."
        return redacted

    def _matches_process(self, process: dict, keywords: list[str]) -> bool:
        haystacks = [
            str(process.get("name", "")),
            str(process.get("command", "")),
            str(process.get("args", "")),
        ]
        normalized_haystacks = [self._normalize_match_text(item) for item in haystacks if item]
        return any(keyword_normalized in haystack for haystack in normalized_haystacks for keyword_normalized in [self._normalize_match_text(keyword) for keyword in keywords])

    def _normalize_match_text(self, value: str) -> str:
        return re.sub(r"[\s\-_]+", "", value.lower())

    def _camera_authorization_status(self) -> str:
        try:
            import AVFoundation  # type: ignore

            status = AVFoundation.AVCaptureDevice.authorizationStatusForMediaType_("vide")
            return {0: "not_determined", 1: "restricted", 2: "denied", 3: "authorized"}.get(int(status), "unknown")
        except Exception:
            return "unknown"

    def _microphone_authorization_status(self) -> str:
        try:
            import AVFoundation  # type: ignore

            status = AVFoundation.AVCaptureDevice.authorizationStatusForMediaType_("soun")
            return {0: "not_determined", 1: "restricted", 2: "denied", 3: "authorized"}.get(int(status), "unknown")
        except Exception:
            return "unknown"

    def _camera_active_via_avfoundation(self) -> bool:
        try:
            import AVFoundation  # type: ignore

            devices = AVFoundation.AVCaptureDevice.devicesWithMediaType_("vide")
            for device in devices or []:
                if hasattr(device, "isInUseByAnotherApplication") and bool(device.isInUseByAnotherApplication()):
                    return True
            return False
        except Exception:
            return False

    def _screen_sharing_enabled(self) -> bool:
        code, stdout, stderr = self.executor(["launchctl", "print-disabled", "system"])
        content = f"{stdout}\n{stderr}".lower()
        if code == 0 and "com.apple.screensharing" in content:
            marker = '"com.apple.screensharing" => false'
            return marker in content or "com.apple.screensharing => false" in content
        code, stdout, _ = self.executor(["/usr/bin/pgrep", "-fl", "screensharingd|ARDAgent"])
        return code == 0 and bool(stdout.strip())

    def _screen_recording_permissions(self) -> list[dict]:
        return self._tcc_permissions("kTCCServiceScreenCapture")

    def _tcc_permissions(self, service: str) -> list[dict]:
        db_path = Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
        if not db_path.exists() or not db_path.is_file():
            return []
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error:
            return []
        try:
            rows = conn.execute(
                """
                SELECT client, auth_value, auth_reason, last_modified
                FROM access
                WHERE service = ?
                ORDER BY client ASC
                """,
                (service,),
            ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            conn.close()
        allowed = []
        for client, auth_value, auth_reason, last_modified in rows:
            if int(auth_value or 0) <= 0:
                continue
            allowed.append(
                {
                    "client": str(client),
                    "auth_value": int(auth_value or 0),
                    "auth_reason": int(auth_reason or 0),
                    "last_modified": int(last_modified or 0),
                }
            )
        return allowed

    def _unified_log_indicators(self) -> list[dict]:
        code, stdout, _stderr = self.executor(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "2m",
                "--style",
                "compact",
                "--predicate",
                'eventMessage CONTAINS[c] "camera" OR eventMessage CONTAINS[c] "microphone" OR eventMessage CONTAINS[c] "screen sharing" OR process CONTAINS[c] "tccd"',
            ]
        )
        if code != 0:
            return []
        indicators: list[dict] = []
        for line in stdout.splitlines():
            lower = line.lower()
            if "camera" in lower:
                indicators.append({"event_type": "camera_activity_suspected", "severity": "info", "confidence": "low", "evidence": "Unified log mentioned camera-related activity."})
            elif "microphone" in lower:
                indicators.append({"event_type": "microphone_activity_suspected", "severity": "info", "confidence": "low", "evidence": "Unified log mentioned microphone-related activity."})
            elif "screen sharing" in lower:
                indicators.append({"event_type": "screen_sharing_enabled", "severity": "info", "confidence": "low", "evidence": "Unified log mentioned screen sharing-related activity."})
        return indicators[:10]

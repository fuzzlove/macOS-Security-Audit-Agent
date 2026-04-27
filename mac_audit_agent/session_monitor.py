from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso


DISPLAY_POWER_RE = re.compile(r'"CurrentPowerState"\s*=\s*(\d+)')
SESSION_LOCK_RE = re.compile(r'"CGSSessionScreenIsLocked"\s*=\s*(\d+)')
CLAMSHELL_RE = re.compile(r'"AppleClamshellState"\s*=\s*(Yes|No|1|0)')
CLAMSHELL_CAUSES_SLEEP_RE = re.compile(r'"AppleClamshellCausesSleep"\s*=\s*(Yes|No|1|0)')
PMSET_TIMESTAMP_RE = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})")


@dataclass
class SessionSnapshot:
    display_state: str = "awake"
    system_power_state: str = "awake"
    session_locked: bool | None = None
    console_user: str = ""
    clamshell_state: str = "unknown"
    clamshell_causes_sleep: str = "unknown"
    recent_markers: set[str] = field(default_factory=set)


def run_command(command: list[str]) -> tuple[int, str, str]:
    executable = Path(command[0])
    if not executable.exists():
        return 127, "", f"command not found: {command[0]}"
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {command[0]}"
    except Exception as exc:
        return 1, "", str(exc)


class SessionMonitor:
    def __init__(self, executor=run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> SessionSnapshot:
        snapshot = SessionSnapshot()
        for field_name, collector, fallback in [
            ("display_state", self._display_state, "unknown"),
            ("system_power_state", self._system_power_state, "unknown"),
            ("session_locked", self._session_locked, None),
            ("console_user", self._console_user, ""),
            ("clamshell_state", self._clamshell_state, "unknown"),
            ("clamshell_causes_sleep", self._clamshell_causes_sleep, "unknown"),
            ("recent_markers", self._recent_markers, set()),
        ]:
            try:
                setattr(snapshot, field_name, collector())
            except Exception:
                setattr(snapshot, field_name, fallback)
        return snapshot

    def evaluate(self, previous: SessionSnapshot | None, current: SessionSnapshot) -> list[BackgroundMonitorEvent]:
        timestamp = utc_now_iso()
        events: list[BackgroundMonitorEvent] = []
        if previous is not None:
            if previous.display_state != current.display_state:
                event_type = "display_wake" if current.display_state == "awake" else "display_sleep"
                confidence = "high" if current.display_state in {"awake", "sleep"} else "medium"
                if current.display_state == "unknown":
                    event_type = "display_state_changed"
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type=event_type,
                        severity="info",
                        source="display_poll",
                        evidence=f"Display state changed from {previous.display_state} to {current.display_state}.",
                        confidence=confidence,
                        recommendation="Review nearby privacy-sensitive events if this display transition was unexpected.",
                        metadata={"previous_display_state": previous.display_state, "current_display_state": current.display_state},
                    )
                )
            if previous.system_power_state != current.system_power_state:
                if current.system_power_state == "sleep":
                    event_type = "system_sleep"
                elif current.system_power_state == "awake":
                    event_type = "system_wake"
                else:
                    event_type = "display_state_changed"
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type=event_type,
                        severity="info",
                        source="pmset_state",
                        evidence=f"System power state changed from {previous.system_power_state} to {current.system_power_state}.",
                        confidence="medium",
                        recommendation="Correlate this with expected user activity and nearby monitor events.",
                        metadata={"previous_system_power_state": previous.system_power_state, "current_system_power_state": current.system_power_state},
                    )
                )
            if previous.session_locked is not None and current.session_locked is not None and previous.session_locked != current.session_locked:
                event_type = "screen_locked" if current.session_locked else "screen_unlocked"
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type=event_type,
                        severity="info",
                        source="session_poll",
                        evidence=f"Session lock state changed to {'locked' if current.session_locked else 'unlocked'}.",
                        confidence="high",
                        recommendation="Confirm the session transition matches expected user activity.",
                        metadata={"session_locked": current.session_locked},
                    )
                )
            if previous.console_user != current.console_user:
                if current.console_user and not previous.console_user:
                    event_type = "screen_unlocked"
                elif previous.console_user and not current.console_user:
                    event_type = "screen_locked"
                else:
                    event_type = "screen_unlocked"
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type=event_type,
                        severity="info",
                        source="console_user",
                        evidence=f"Console user changed from {previous.console_user or 'none'} to {current.console_user or 'none'}.",
                        confidence="medium",
                        recommendation="Confirm the console-user transition matches expected login/logout activity.",
                        metadata={"previous_console_user": previous.console_user, "current_console_user": current.console_user},
                    )
                )
            if previous.clamshell_state != current.clamshell_state:
                if current.clamshell_state == "closed":
                    event_type = "possible_lid_closed"
                elif current.clamshell_state == "open":
                    event_type = "possible_lid_opened"
                else:
                    event_type = "clamshell_state_changed"
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type=event_type,
                        severity="info",
                        source="ioreg_poll",
                        evidence=f"Clamshell state changed from {previous.clamshell_state} to {current.clamshell_state}.",
                        confidence="medium" if current.clamshell_state != "unknown" else "low",
                        recommendation="Correlate the clamshell transition with display and session activity.",
                        metadata={"previous_clamshell_state": previous.clamshell_state, "current_clamshell_state": current.clamshell_state},
                    )
                )
            elif previous.clamshell_causes_sleep != current.clamshell_causes_sleep and current.clamshell_causes_sleep != "unknown":
                events.append(
                    self._event(
                        timestamp=timestamp,
                        event_type="clamshell_state_changed",
                        severity="info",
                        source="ioreg_poll",
                        evidence=f"Clamshell sleep behavior changed from {previous.clamshell_causes_sleep} to {current.clamshell_causes_sleep}.",
                        confidence="low",
                        recommendation="Correlate the clamshell behavior change with power and display activity.",
                        metadata={"previous_clamshell_causes_sleep": previous.clamshell_causes_sleep, "current_clamshell_causes_sleep": current.clamshell_causes_sleep},
                    )
                )

        new_markers = sorted(current.recent_markers - (previous.recent_markers if previous else set()))
        for marker in new_markers:
            kind, when = marker.split("|", 1)
            event_type = {
                "display_sleep": "display_sleep",
                "display_wake": "display_wake",
                "system_sleep": "system_sleep",
                "system_wake": "system_wake",
                "possible_lid_closed": "possible_lid_closed",
                "possible_lid_opened": "possible_lid_opened",
            }.get(kind, "display_state_changed")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type=event_type,
                    severity="info",
                    source="pmset_log",
                    evidence=f"pmset/log reported {kind} at {when}.",
                    confidence="medium" if "lid" not in kind else "low",
                    recommendation="Correlate this with expected user activity and recent app launches if needed.",
                    metadata={"pmset_kind": kind, "pmset_timestamp": when},
                )
            )
        return events

    def _event(self, *, timestamp: str, event_type: str, severity: str, source: str, evidence: str, confidence: str, recommendation: str, metadata: dict) -> BackgroundMonitorEvent:
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{source}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source=source,
            evidence=evidence,
            confidence=confidence,
            recommendation=recommendation,
            metadata_json=json.dumps(self._sanitize_metadata(metadata), sort_keys=True),
        )

    def _sanitize_metadata(self, metadata: dict) -> dict:
        cleaned = dict(metadata)
        cleaned.pop("screen_content", None)
        cleaned.pop("image_bytes", None)
        return cleaned

    def _display_state(self) -> str:
        code, stdout, _ = self.executor(["/usr/sbin/ioreg", "-r", "-n", "IODisplayWrangler", "-d", "1"])
        if code != 0:
            return "unknown"
        match = DISPLAY_POWER_RE.search(stdout)
        if not match:
            return "unknown"
        return "awake" if int(match.group(1)) > 3 else "sleep"

    def _system_power_state(self) -> str:
        code, stdout, _ = self.executor(["/usr/bin/pmset", "-g", "ps"])
        if code != 0:
            return "unknown"
        lower = stdout.lower()
        if "sleep" in lower:
            return "sleep"
        if "discharging" in lower or "ac power" in lower or "battery power" in lower:
            return "awake"
        return "unknown"

    def _session_locked(self) -> bool | None:
        code, stdout, _ = self.executor(["/usr/bin/python3", "-c", "from Quartz import CGSessionCopyCurrentDictionary as f; import json; print(f() or {})"])
        if code == 0:
            match = SESSION_LOCK_RE.search(stdout)
            if match:
                return match.group(1) == "1"
        cgsession = Path("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession")
        if cgsession.exists():
            code, stdout, _ = self.executor([str(cgsession), "-current"])
            if code == 0:
                match = SESSION_LOCK_RE.search(stdout)
                if match:
                    return match.group(1) == "1"
        code, stdout, _ = self.executor(["/usr/bin/pmset", "-g", "assertions"])
        if code == 0:
            lower = stdout.lower()
            if "userisactive" in lower or "preventuseridle" in lower:
                return False
        code, stdout, _ = self.executor(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "2m",
                "--style",
                "compact",
                "--predicate",
                'eventMessage CONTAINS[c] "locked" OR eventMessage CONTAINS[c] "unlocked"',
            ]
        )
        if code == 0:
            lower = stdout.lower()
            if "locked" in lower and "unlocked" not in lower:
                return True
            if "unlocked" in lower:
                return False
        return None

    def _console_user(self) -> str:
        code, stdout, _ = self.executor(["/usr/bin/stat", "-f", "%Su", "/dev/console"])
        return stdout.strip() if code == 0 else ""

    def _clamshell_state(self) -> str:
        code, stdout, _ = self.executor(["/usr/sbin/ioreg", "-r", "-k", "AppleClamshellState", "-d", "4"])
        if code != 0:
            return "unknown"
        match = CLAMSHELL_RE.search(stdout)
        if not match:
            return "unknown"
        value = match.group(1).lower()
        return "closed" if value in {"yes", "1"} else "open"

    def _clamshell_causes_sleep(self) -> str:
        code, stdout, _ = self.executor(["/usr/sbin/ioreg", "-r", "-k", "AppleClamshellCausesSleep", "-d", "4"])
        if code != 0:
            return "unknown"
        match = CLAMSHELL_CAUSES_SLEEP_RE.search(stdout)
        if not match:
            return "unknown"
        value = match.group(1).lower()
        return "yes" if value in {"yes", "1"} else "no"

    def _recent_markers(self) -> set[str]:
        markers: set[str] = set()
        code, stdout, _ = self.executor(["/usr/bin/pmset", "-g", "log"])
        if code == 0:
            markers.update(self._parse_pmset_markers(stdout))
        if not markers:
            code, stdout, _ = self.executor(
                [
                    "/usr/bin/log",
                    "show",
                    "--last",
                    "5m",
                    "--style",
                    "compact",
                    "--predicate",
                    'eventMessage CONTAINS[c] "Display is turned off" OR eventMessage CONTAINS[c] "Display is turned on" OR eventMessage CONTAINS[c] "Wake" OR eventMessage CONTAINS[c] "Sleep"',
                ]
            )
            if code == 0:
                markers.update(self._parse_log_markers(stdout))
        return markers

    def _parse_pmset_markers(self, text: str) -> set[str]:
        markers: set[str] = set()
        for line in text.splitlines()[-200:]:
            lower = line.lower()
            ts_match = PMSET_TIMESTAMP_RE.search(line)
            timestamp = ts_match.group("timestamp") if ts_match else "unknown"
            if "display is turned off" in lower:
                markers.add(f"display_sleep|{timestamp}")
            if "display is turned on" in lower:
                markers.add(f"display_wake|{timestamp}")
            if "entering sleep state due to" in lower and "clamshell sleep" in lower:
                markers.add(f"possible_lid_closed|{timestamp}")
            if " sleep " in lower or lower.strip().endswith(" sleep"):
                markers.add(f"system_sleep|{timestamp}")
            if " wake " in lower or " darkwake " in lower or "wake from" in lower:
                markers.add(f"system_wake|{timestamp}")
            if "lid close" in lower or "clamshell closed" in lower or "clamshell sleep" in lower:
                markers.add(f"possible_lid_closed|{timestamp}")
            if "lid open" in lower or "clamshell open" in lower or "ec.lidopen" in lower or "due to ec.lidopen" in lower:
                markers.add(f"possible_lid_opened|{timestamp}")
        return markers

    def _parse_log_markers(self, text: str) -> set[str]:
        markers: set[str] = set()
        for line in text.splitlines()[-200:]:
            lower = line.lower()
            ts_match = PMSET_TIMESTAMP_RE.search(line)
            timestamp = ts_match.group("timestamp") if ts_match else "unknown"
            if "display is turned off" in lower:
                markers.add(f"display_sleep|{timestamp}")
            if "display is turned on" in lower:
                markers.add(f"display_wake|{timestamp}")
            if "clamshell" in lower and "sleep" in lower:
                markers.add(f"possible_lid_closed|{timestamp}")
            if "lidopen" in lower or ("clamshell" in lower and "open" in lower):
                markers.add(f"possible_lid_opened|{timestamp}")
            if "wake" in lower:
                markers.add(f"system_wake|{timestamp}")
            if "sleep" in lower:
                markers.add(f"system_sleep|{timestamp}")
        return markers

from __future__ import annotations

import json
import plistlib
import re
import stat
from pathlib import Path

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import (
    BaselineComparison,
    BaselineDelta,
    FileIssueSnapshot,
    HistoryIndicator,
    LaunchItemSnapshot,
    PermissionSnapshot,
    PortSnapshot,
    ProcessSnapshot,
    Severity,
    UserSnapshot,
    safe_int,
)


HISTORY_PATTERNS: list[tuple[str, str, str]] = [
    ("curl_pipe_sh", r"curl\s+[^|]+\|\s*(?:/bin/)?sh\b", "Piping remote content directly to a shell can execute unreviewed code."),
    ("wget_pipe_sh", r"wget\s+[^|]+\|\s*(?:/bin/)?sh\b", "Piping remote content directly to a shell can execute unreviewed code."),
    ("base64_decode", r"base64\s+-d\b|base64\s+--decode\b", "Base64 decoding can be used to hide payload delivery or scripts."),
    ("chmod_777", r"chmod\s+777\b", "Overly broad permissions can enable tampering."),
    ("chown_root", r"chown\s+root\b", "Ownership changes to root may indicate privileged persistence setup."),
    ("sudoers_edit", r"(?:visudo|/etc/sudoers|sudoers\.d)", "Sudo policy edits directly affect privilege escalation paths."),
    ("launchctl_load", r"launchctl\s+(?:load|bootstrap)\b", "Launchctl can establish persistence or background execution."),
    ("osascript", r"\bosascript\b", "AppleScript can automate sensitive UI and system actions."),
    ("netcat", r"\b(?:nc|netcat)\b", "Netcat is commonly used for ad hoc transfer, shells, and tunneling."),
    ("inline_code", r"\b(?:python|perl|ruby)\s+-[ce]\b", "Inline interpreter execution can hide short-lived payloads."),
    ("reverse_shell", r"/dev/tcp/|bash\s+-i|nc\s+.*\s-e\s+|socket\.socket\(", "Reverse-shell patterns can indicate interactive remote control."),
    ("encoded_payload", r"(?:eval\(|openssl\s+enc|xxd\s+-r|python\s+-c\s+.*base64)", "Encoded or decoded payload staging can hide intent."),
    ("persistence_path", r"LaunchAgents|LaunchDaemons|PrivilegedHelperTools", "Persistence paths are frequently used to retain execution."),
]

APPLE_PROCESS_LOOKALIKES = {
    "softwareupdate",
    "launchservicesd",
    "securityd",
    "mdworker",
    "xpcproxy",
    "cfprefsd",
    "loginwindow",
}
SUSPICIOUS_BASE_PATHS = ("/tmp", "/var/tmp", "/private/tmp", "/Users/Shared")
TRUSTED_PREFIXES = ("/System/", "/usr/libexec/", "/usr/bin/", "/bin/", "/sbin/", "/Library/Apple/")


def redact_sensitive_text(text: str, config: AuditConfig) -> str:
    redacted = text
    if config.redact_url_secrets:
        redacted = re.sub(r"([?&](?:token|auth|key|secret|sig|signature|password)=)[^&\s]+", r"\1[REDACTED]", redacted, flags=re.IGNORECASE)
    if config.redact_ips:
        redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]", redacted)
    if config.redact_paths:
        redacted = re.sub(r"/Users/[^/\s]+", "/Users/[REDACTED_USER]", redacted)
        redacted = re.sub(r"~/(?:[^\s]+)", "~/[REDACTED_PATH]", redacted)
    if config.redact_usernames:
        redacted = re.sub(r"\buser(?:name)?\s*[=:]\s*[^\s]+", "user=[REDACTED]", redacted, flags=re.IGNORECASE)
        redacted = re.sub(r"\b(?:su|sudo)\s+-u\s+[A-Za-z0-9._-]+", lambda m: m.group(0).rsplit(" ", 1)[0] + " [REDACTED_USER]", redacted)
    return redacted


def extract_history_indicators(history_text: str, source_path: str, shell_type: str, config: AuditConfig) -> list[HistoryIndicator]:
    indicators: list[HistoryIndicator] = []
    counts: dict[str, int] = {}
    snippets: dict[str, str] = {}
    for line in history_text.splitlines():
        lowered = line.strip()
        if not lowered:
            continue
        for pattern_id, pattern, warning in HISTORY_PATTERNS:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                counts[pattern_id] = counts.get(pattern_id, 0) + 1
                if pattern_id not in snippets:
                    snippet = lowered if config.include_history_context else lowered[:220]
                    snippets[pattern_id] = redact_sensitive_text(snippet, config)
    for pattern_id, _, warning in HISTORY_PATTERNS:
        if pattern_id in counts:
            indicators.append(
                HistoryIndicator(
                    source_path=source_path,
                    shell_type=shell_type,
                    pattern_id=pattern_id,
                    match_count=counts[pattern_id],
                    snippet=snippets[pattern_id],
                    warning=warning,
                    context_included=config.include_history_context,
                )
            )
    return indicators


def parse_lsof_listening_output(text: str, config: AuditConfig) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        process_name = parts[0]
        pid = safe_int(parts[1])
        if pid is None:
            continue
        user = parts[2]
        name_field = parts[8]
        protocol_match = re.search(r"\b(TCP|UDP)\b", line)
        protocol = protocol_match.group(1) if protocol_match else parts[7]
        state_match = re.search(r"\(([^)]+)\)\s*$", line)
        state = state_match.group(1) if state_match else ""
        local_address = re.sub(r"\s*\([^)]+\)\s*$", "", name_field).split("->", 1)[0].strip()
        port = _extract_port(local_address)
        if port is None:
            continue
        concern = config.concerning_ports.get(port, "")
        severity, next_checks = detect_suspicious_listening_port(port, local_address, concern)
        rows.append(
            {
                "process": process_name,
                "pid": pid,
                "user": user,
                "protocol": protocol,
                "local_address": local_address,
                "port": port,
                "state": state,
                "raw": redact_sensitive_text(line, config),
                "concern": concern,
                "severity": severity,
                "recommended_next_checks": next_checks,
            }
        )
    return rows


def parse_lsof_udp_output(text: str, config: AuditConfig) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        pid = safe_int(parts[1])
        if pid is None:
            continue
        process_name = parts[0]
        user = parts[2]
        protocol = parts[7]
        local_address = parts[-1].split("->", 1)[0]
        port = _extract_port(local_address)
        if port is None:
            continue
        concern = config.concerning_ports.get(port, "")
        severity, next_checks = detect_suspicious_listening_port(port, local_address, concern)
        rows.append(
            {
                "process": process_name,
                "pid": pid,
                "user": user,
                "protocol": protocol,
                "local_address": local_address,
                "port": port,
                "state": "UDP",
                "raw": redact_sensitive_text(line, config),
                "concern": concern,
                "severity": severity,
                "recommended_next_checks": next_checks,
            }
        )
    return rows


def parse_netstat_tcp_output(text: str, config: AuditConfig) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("tcp"):
            continue
        parts = stripped.split()
        if len(parts) < 6:
            continue
        local_address = parts[3]
        state = parts[5] if len(parts) > 5 else ""
        if state.upper() != "LISTEN":
            continue
        port = _extract_port(local_address)
        if port is None:
            continue
        concern = config.concerning_ports.get(port, "")
        severity, next_checks = detect_suspicious_listening_port(port, local_address, concern)
        rows.append(
            {
                "process": "unknown",
                "pid": None,
                "user": "",
                "protocol": "TCP",
                "local_address": local_address,
                "port": port,
                "state": state,
                "raw": redact_sensitive_text(line, config),
                "concern": concern,
                "severity": severity,
                "recommended_next_checks": next_checks,
            }
        )
    return rows


def detect_suspicious_listening_port(port: int, local_address: str, concern: str) -> tuple[Severity, str]:
    if not concern:
        return "info", "Validate whether the listener belongs to an expected local service."
    if port in {2375, 4444}:
        severity: Severity = "high"
    elif local_address.startswith("127.0.0.1") or local_address.startswith("localhost"):
        severity = "low"
    else:
        severity = "medium"
    next_checks = "Confirm the owning process, whether the service should be listening, and whether network exposure is limited to localhost."
    return severity, next_checks


def _extract_port(local_address: str) -> int | None:
    match = re.search(r":(\d+)(?:\s|$)", local_address)
    if match:
        return safe_int(match.group(1))
    match = re.search(r"\.(\d+)$", local_address)
    if match:
        return safe_int(match.group(1))
    match = re.search(r":(\d+)$", local_address)
    if match:
        return safe_int(match.group(1))
    return None


def parse_ps_output(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 3)
        if len(parts) != 4 or parts[0] == "PID":
            continue
        pid, ppid, user, command_path = parts
        if safe_int(pid) is None or safe_int(ppid) is None:
            continue
        records.append({"pid": pid, "ppid": ppid, "user": user, "command_path": command_path})
    return records


def parse_ps_axo_output(text: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 4)
        if len(parts) < 4:
            continue
        user, pid, ppid, comm = parts[:4]
        args = parts[4] if len(parts) == 5 else ""
        if safe_int(pid) is None:
            continue
        records.append(
            {
                "user": user,
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "args": args,
                "path": comm,
                "suspicious_reasons": [],
                "command_path": comm,
            }
        )
    return records


def score_process_binary_trust(command_path: str, *, signed_status: str, process_name: str | None = None) -> tuple[str, list[str], int, str]:
    reasons: list[str] = []
    process_name = process_name or Path(command_path).name
    score = 100
    if command_path.startswith(SUSPICIOUS_BASE_PATHS):
        reasons.append("running_from_writable_staging_path")
        score -= 45
    if command_path.startswith("/Users/") and "/Applications/" not in command_path:
        reasons.append("running_from_user_space")
        score -= 20
    if Path(command_path).name.startswith("."):
        reasons.append("hidden_executable_name")
        score -= 20
    if process_name.lower() in APPLE_PROCESS_LOOKALIKES and not command_path.startswith(TRUSTED_PREFIXES):
        reasons.append("apple_like_process_name")
        score -= 20
    if signed_status == "unsigned":
        reasons.append("unsigned_process_binary")
        score -= 35
    elif signed_status == "signed":
        score += 5
    if command_path.startswith(TRUSTED_PREFIXES) and signed_status in {"signed", "unknown"} and not reasons:
        return "trusted", [], 95 if signed_status == "signed" else 88, "Trusted system or application path with no suspicious indicators."
    score = max(0, min(100, score))
    if reasons:
        trust_level = "untrusted" if "running_from_writable_staging_path" in reasons or "unsigned_process_binary" in reasons else "review"
        summary = "Binary trust score reduced by: " + ", ".join(reasons)
        return trust_level, reasons, score, summary
    return "review", ["nonstandard_process_path"], 65, "Nonstandard executable path without stronger risk indicators."


def detect_process_trust(command_path: str, *, signed_status: str, process_name: str | None = None) -> tuple[str, list[str]]:
    trust_level, reasons, _score, _summary = score_process_binary_trust(
        command_path,
        signed_status=signed_status,
        process_name=process_name,
    )
    return trust_level, reasons


def build_process_snapshot(record: dict[str, str], signed_status: str) -> ProcessSnapshot:
    process_name = Path(record["command_path"]).name or record["command_path"]
    trust_level, reasons, trust_score, trust_summary = score_process_binary_trust(
        record["command_path"],
        signed_status=signed_status,
        process_name=process_name,
    )
    return ProcessSnapshot(
        pid=safe_int(record["pid"]),
        ppid=safe_int(record["ppid"]),
        user=record["user"],
        command_path=record["command_path"],
        process_name=process_name,
        signed_status=signed_status,
        trust_level=trust_level,  # type: ignore[arg-type]
        args=record.get("args", ""),
        reasons=reasons,
        trust_score=trust_score,
        trust_summary=trust_summary,
    )


def build_port_snapshot(row: dict[str, object]) -> PortSnapshot:
    concern = str(row.get("concern", ""))
    severity = row.get("severity", "info")
    next_checks = str(row.get("recommended_next_checks", ""))
    return PortSnapshot(
        process_name=str(row.get("process", "")),
        pid=safe_int(row.get("pid")),
        local_address=str(row.get("local_address", "")),
        port=safe_int(row.get("port")),
        protocol=str(row.get("protocol", "")),
        state=str(row.get("state", "")),
        user=str(row.get("user", "")),
        concern=concern,
        severity=severity if severity in {"info", "low", "medium", "high", "critical"} else "info",  # type: ignore[arg-type]
        recommended_next_checks=next_checks,
        raw=str(row.get("raw", "")),
    )


def build_process_snapshot_from_row(row: dict[str, object], signed_status: str = "unknown") -> ProcessSnapshot:
    command_path = str(row.get("path") or row.get("comm") or "")
    process_name = Path(command_path).name or command_path
    trust_level, reasons, trust_score, trust_summary = score_process_binary_trust(
        command_path,
        signed_status=signed_status,
        process_name=process_name,
    )
    return ProcessSnapshot(
        pid=safe_int(row.get("pid")),
        ppid=safe_int(row.get("ppid")),
        user=str(row.get("user", "")),
        command_path=command_path,
        process_name=process_name,
        signed_status=signed_status,
        trust_level=trust_level,  # type: ignore[arg-type]
        args=str(row.get("args", "")),
        reasons=list(row.get("suspicious_reasons", [])) or reasons,
        trust_score=safe_int(row.get("trust_score")) or trust_score,
        trust_summary=str(row.get("trust_summary", "")) or trust_summary,
    )


def score_file_binary_trust(
    path: str,
    *,
    executable: bool,
    world_writable: bool,
    hidden: bool,
    signed_status: str,
) -> tuple[int, str, str]:
    score = 85 if signed_status == "signed" else 65 if signed_status == "unknown" else 35
    reasons: list[str] = []
    if executable:
        score -= 5
    if world_writable:
        score -= 30
        reasons.append("world_writable")
    if hidden:
        score -= 20
        reasons.append("hidden")
    if signed_status == "unsigned":
        reasons.append("unsigned")
    if path.startswith(SUSPICIOUS_BASE_PATHS):
        score -= 25
        reasons.append("writable_staging_path")
    score = max(0, min(100, score))
    label = "trusted" if score >= 80 else "review" if score >= 45 else "untrusted"
    summary = "Binary trust score " + str(score)
    if reasons:
        summary += " because of " + ", ".join(reasons)
    return score, label, summary


def parse_user_records(
    users_json: str,
    *,
    admin_users: set[str],
    hidden_users: set[str],
    locked_users: set[str] | None = None,
    disabled_users: set[str] | None = None,
    groups_by_user: dict[str, list[str]] | None = None,
) -> list[UserSnapshot]:
    payload = json.loads(users_json)
    locked_users = locked_users or set()
    disabled_users = disabled_users or set()
    groups_by_user = groups_by_user or {}
    users: list[UserSnapshot] = []
    for record in payload:
        username = record["username"]
        uid = safe_int(record.get("uid"))
        gid = safe_int(record.get("gid"))
        if uid is None or gid is None:
            continue
        shell = record.get("shell", "")
        home = record.get("home", "")
        users.append(
            UserSnapshot(
                username=username,
                uid=uid,
                gid=gid,
                shell=shell,
                home=home,
                hidden=username in hidden_users,
                admin=username in admin_users,
                locked=username in locked_users,
                disabled=username in disabled_users,
                unusual_uid=uid not in {0} and uid < 500,
                unusual_gid=gid < 20,
                shell_enabled=shell not in {"", "/usr/bin/false", "/usr/bin/nologin"},
                suspicious_home=not home.startswith("/Users/") and username not in {"root", "nobody", "_spotlight"},
                groups=groups_by_user.get(username, []),
            )
        )
    return users


def summarize_authorized_keys(lines: list[str]) -> tuple[int, list[str], list[str]]:
    key_types: list[str] = []
    comments: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            key_types.append(parts[0])
        if len(parts) >= 3:
            comment = parts[2]
            if "@" in comment and len(comment) < 128:
                comments.append(comment)
    return len(key_types), key_types, comments


def parse_sudoers(content: str, source_path: str) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("Defaults") or line.startswith("includedir"):
            continue
        match = re.match(r"(?P<principal>\S+)\s+\S+\s*=\s*\((?P<runas>[^)]*)\)\s*(?P<spec>.+)", line)
        if match:
            rules.append(
                {
                    "principal": match.group("principal"),
                    "runas": match.group("runas") or "ALL",
                    "spec": match.group("spec"),
                    "source": source_path,
                }
            )
    return rules


def detect_sudoers_risk(rule: dict[str, str]) -> tuple[Severity, str] | None:
    spec = rule["spec"].upper()
    if "NOPASSWD" in spec and "ALL" in spec:
        return "high", "Passwordless sudo with broad scope increases the impact of account compromise."
    if "ALL" in spec:
        return "medium", "Broad sudo scope should be reviewed to confirm it is intentional."
    return None


def detect_weak_permission(path: str, mode: int) -> PermissionSnapshot | None:
    basename = Path(path).name
    mode_bits = stat.S_IMODE(mode)
    mode_octal = format(mode_bits, "04o")
    group_write = bool(mode_bits & stat.S_IWGRP)
    other_write = bool(mode_bits & stat.S_IWOTH)
    other_read = bool(mode_bits & stat.S_IROTH)

    if basename == ".ssh" and (group_write or other_write or other_read):
        return PermissionSnapshot(path=path, mode=mode_octal, issue="SSH directory is too permissive.", severity="high")
    if basename == "authorized_keys" and (group_write or other_write or other_read):
        return PermissionSnapshot(path=path, mode=mode_octal, issue="authorized_keys is readable or writable by non-owner.", severity="high")
    if basename in {".zshrc", ".bash_profile", ".bashrc", ".zprofile"} and other_write:
        return PermissionSnapshot(path=path, mode=mode_octal, issue="Shell profile is world-writable.", severity="high")
    if "LaunchAgents" in path or "LaunchDaemons" in path:
        if other_write or group_write:
            return PermissionSnapshot(path=path, mode=mode_octal, issue="Launch item path is writable by non-owner.", severity="high")
    if any(path.startswith(prefix) for prefix in ["/tmp", "/var/tmp", "/private/tmp", "/Users/Shared"]) and other_write:
        return PermissionSnapshot(path=path, mode=mode_octal, issue="Sensitive temp/shared path is world-writable.", severity="medium")
    return None


def detect_suspicious_writable_executable(path: str, *, directory_world_writable: bool, executable: bool) -> FileIssueSnapshot | None:
    if not executable or not directory_world_writable:
        return None
    trust_score, trust_label, trust_summary = score_file_binary_trust(
        path,
        executable=True,
        world_writable=True,
        hidden=Path(path).name.startswith("."),
        signed_status="unknown",
    )
    return FileIssueSnapshot(
        path=path,
        issue_type="writable_directory_executable",
        modified_at="",
        executable=True,
        world_writable=True,
        hidden=Path(path).name.startswith("."),
        signed_status="unknown",
        trust_score=trust_score,
        trust_label=trust_label,
        trust_summary=trust_summary,
    )


def detect_suspicious_file(
    path: str,
    *,
    executable: bool,
    world_writable: bool,
    hidden: bool,
    signed_status: str,
    modified_at: str,
) -> FileIssueSnapshot | None:
    name = Path(path).name.lower()
    suspicious_name = name in APPLE_PROCESS_LOOKALIKES or name.startswith(".")
    if not any([executable, world_writable, hidden, suspicious_name, signed_status == "unsigned"]):
        return None
    issue_type = []
    if executable:
        issue_type.append("executable")
    if world_writable:
        issue_type.append("world_writable")
    if hidden:
        issue_type.append("hidden")
    if signed_status == "unsigned":
        issue_type.append("unsigned")
    if suspicious_name:
        issue_type.append("apple_like_name")
    trust_score, trust_label, trust_summary = score_file_binary_trust(
        path,
        executable=executable,
        world_writable=world_writable,
        hidden=hidden,
        signed_status=signed_status,
    )
    return FileIssueSnapshot(
        path=path,
        issue_type=",".join(issue_type),
        modified_at=modified_at,
        executable=executable,
        world_writable=world_writable,
        hidden=hidden,
        signed_status=signed_status,
        trust_score=trust_score,
        trust_label=trust_label,
        trust_summary=trust_summary,
    )


def parse_launchd_plist(plist_bytes: bytes, path: str) -> LaunchItemSnapshot:
    payload = plistlib.loads(plist_bytes)
    label = str(payload.get("Label", Path(path).stem))
    program = ""
    if isinstance(payload.get("Program"), str):
        program = payload["Program"]
    elif isinstance(payload.get("ProgramArguments"), list) and payload["ProgramArguments"]:
        program = str(payload["ProgramArguments"][0])
    program_arguments = [str(item) for item in payload.get("ProgramArguments", []) if item is not None]
    run_at_load = bool(payload.get("RunAtLoad", False))
    keep_alive_value = payload.get("KeepAlive", False)
    keep_alive = bool(keep_alive_value) or isinstance(keep_alive_value, dict)
    suspicious, reasons = detect_suspicious_launch_item(path=path, label=label, program=program, program_arguments=program_arguments)
    return LaunchItemSnapshot(
        path=path,
        label=label,
        program=program,
        program_arguments=program_arguments,
        run_at_load=run_at_load,
        keep_alive=keep_alive,
        suspicious=suspicious,
        reasons=reasons,
    )


def detect_suspicious_launch_item(*, path: str, label: str, program: str, program_arguments: list[str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    lower_label = label.lower()
    if program.startswith(SUSPICIOUS_BASE_PATHS):
        reasons.append("launch_program_in_writable_path")
    if program.startswith("/Users/"):
        reasons.append("launch_program_in_user_space")
    if Path(program).name.startswith("."):
        reasons.append("launch_hidden_program")
    if lower_label in APPLE_PROCESS_LOOKALIKES and not program.startswith(TRUSTED_PREFIXES):
        reasons.append("launch_apple_like_label")
    if any("LaunchAgents" in arg or "LaunchDaemons" in arg for arg in program_arguments):
        reasons.append("launch_references_persistence_path")
    if "/usr/bin/osascript" in program or any("osascript" in arg for arg in program_arguments):
        reasons.append("launch_uses_osascript")
    return bool(reasons), reasons


def compare_snapshots(
    previous_ports: list[PortSnapshot],
    current_ports: list[PortSnapshot],
    previous_users: list[UserSnapshot],
    current_users: list[UserSnapshot],
    previous_permissions: list[PermissionSnapshot],
    current_permissions: list[PermissionSnapshot],
    previous_history: list[HistoryIndicator],
    current_history: list[HistoryIndicator],
    previous_files: list[FileIssueSnapshot],
    current_files: list[FileIssueSnapshot],
    previous_launch_items: set[str],
    current_launch_items: set[str],
    previous_processes: list[ProcessSnapshot] | None = None,
    current_processes: list[ProcessSnapshot] | None = None,
    previous_launch_snapshots: list[LaunchItemSnapshot] | None = None,
    current_launch_snapshots: list[LaunchItemSnapshot] | None = None,
    previous_findings: list | None = None,
    current_findings: list | None = None,
) -> BaselineComparison:
    comparison = BaselineComparison()
    previous_port_keys = {item.key() for item in previous_ports}
    current_port_keys = {item.key() for item in current_ports}
    for item in current_ports:
        if item.key() not in previous_port_keys:
            comparison.new_ports.append(BaselineDelta("new_port", str(item.key()), f"{item.process_name} listening on {item.local_address}"))
    for item in previous_ports:
        if item.key() not in current_port_keys:
            comparison.removed_ports.append(BaselineDelta("removed_port", str(item.key()), f"{item.process_name} no longer listening on {item.local_address}"))

    previous_users_map = {item.key(): item for item in previous_users}
    current_user_keys = {item.key() for item in current_users}
    for item in current_users:
        prior = previous_users_map.get(item.key())
        if prior is None:
            comparison.new_users.append(BaselineDelta("new_user", item.username, f"uid={item.uid} shell={item.shell}"))
        elif not prior.admin and item.admin:
            comparison.new_admin_users.append(BaselineDelta("new_admin_user", item.username, "User gained admin membership."))
    for item in previous_users:
        if item.key() not in current_user_keys:
            comparison.removed_users.append(BaselineDelta("removed_user", item.username, "User no longer present in current scan."))

    for item in sorted(current_launch_items - previous_launch_items):
        comparison.new_launch_items.append(BaselineDelta("new_launch_item", item, "New LaunchAgent or LaunchDaemon observed."))
    for item in sorted(previous_launch_items - current_launch_items):
        comparison.removed_launch_items.append(BaselineDelta("removed_launch_item", item, "LaunchAgent or LaunchDaemon no longer present."))

    previous_permissions_map = {item.key(): item for item in previous_permissions}
    for item in current_permissions:
        prior = previous_permissions_map.get(item.key())
        if prior is None or prior.mode != item.mode or prior.issue != item.issue:
            comparison.changed_permissions.append(BaselineDelta("permission_change", item.path, f"{prior.mode if prior else 'none'} -> {item.mode}"))

    previous_history_keys = {item.key() for item in previous_history}
    for item in current_history:
        if item.key() not in previous_history_keys:
            comparison.new_history_indicators.append(BaselineDelta("new_history_indicator", str(item.key()), item.pattern_id))

    previous_file_keys = {item.key() for item in previous_files}
    previous_files_map = {item.key(): item for item in previous_files}
    for item in current_files:
        if item.key() not in previous_file_keys:
            comparison.new_suspicious_files.append(BaselineDelta("new_suspicious_file", item.path, item.issue_type))
        else:
            prior = previous_files_map[item.key()]
            if getattr(prior, "sha256", "") and getattr(item, "sha256", "") and prior.sha256 != item.sha256:
                comparison.changed_hashes.append(BaselineDelta("changed_hash", item.path, f"{prior.sha256} -> {item.sha256}"))

    previous_processes = previous_processes or []
    current_processes = current_processes or []
    previous_process_keys = {item.key() for item in previous_processes if item.trust_level != "trusted"}
    for item in current_processes:
        if item.trust_level != "trusted" and item.key() not in previous_process_keys:
            comparison.new_suspicious_processes.append(BaselineDelta("new_suspicious_process", str(item.key()), ",".join(item.reasons)))

    previous_launch_snapshots = previous_launch_snapshots or []
    current_launch_snapshots = current_launch_snapshots or []
    previous_launch_keys = {item.key() for item in previous_launch_snapshots if item.suspicious}
    for item in current_launch_snapshots:
        if item.suspicious and item.key() not in previous_launch_keys:
            comparison.new_suspicious_launch_items.append(BaselineDelta("new_suspicious_launch_item", item.path, ",".join(item.reasons)))

    previous_findings = previous_findings or []
    current_findings = current_findings or []
    previous_finding_keys = {getattr(item, "title", None) or item.get("title"): getattr(item, "category", None) or item.get("category") for item in previous_findings}
    current_finding_keys = {(getattr(item, "title", None) or item.get("title"), getattr(item, "category", None) or item.get("category")) for item in current_findings}
    for title, category in previous_finding_keys.items():
        key = (title, category)
        if key not in current_finding_keys:
            comparison.resolved_findings.append(BaselineDelta("resolved_finding", f"{category}:{title}", "Finding no longer present in current scan."))
    comparison.high_risk_change_count = sum(
        len(group)
        for group in [
            comparison.new_admin_users,
            comparison.new_launch_items,
            comparison.new_suspicious_files,
            comparison.new_suspicious_processes,
            comparison.new_suspicious_launch_items,
            comparison.changed_hashes,
        ]
    )
    comparison.drift_score = min(
        100,
        (
            len(comparison.new_ports) * 4
            + len(comparison.removed_ports) * 2
            + len(comparison.new_users) * 6
            + len(comparison.removed_users) * 3
            + len(comparison.new_admin_users) * 16
            + len(comparison.new_launch_items) * 12
            + len(comparison.removed_launch_items) * 4
            + len(comparison.changed_permissions) * 8
            + len(comparison.changed_hashes) * 14
            + len(comparison.new_history_indicators) * 5
            + len(comparison.new_suspicious_files) * 12
            + len(comparison.new_suspicious_processes) * 10
            + len(comparison.new_suspicious_launch_items) * 14
        ),
    )
    if comparison.drift_score >= 45 or comparison.high_risk_change_count >= 3:
        comparison.drift_label = "high drift"
    elif comparison.drift_score >= 20 or comparison.high_risk_change_count >= 1:
        comparison.drift_label = "moderate drift"
    else:
        comparison.drift_label = "stable"
    comparison.drift_summary = (
        f"{comparison.total_changes()} total changes, "
        f"{comparison.high_risk_change_count} high-risk changes, "
        f"drift score {comparison.drift_score}/100."
    )
    return comparison


def severity_rank(severity: Severity) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[severity]

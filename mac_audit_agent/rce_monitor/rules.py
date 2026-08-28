from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .models import TelemetryEvent

INTERPRETERS = {"sh", "bash", "zsh", "python", "python3", "perl", "ruby", "osascript", "node", "php"}
UNEXPECTED_UTILITIES = INTERPRETERS | {"curl", "wget", "nc", "ncat", "socat", "clang", "gcc", "ld", "launchctl", "installer"}
SERVICE_NAMES = {"httpd", "nginx", "apache2", "php-fpm", "java", "tomcat", "mysqld", "postgres", "redis-server", "sshd", "cupsd", "smbd", "ftpd"}
RISK_PATHS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/", "/uploads/", "/upload/", "/cache/", "/Library/WebServer/Documents/")
OBFUSCATION = re.compile(r"(?i)(base64|frombase64|eval\s*\(|-enc(?:odedcommand)?\b|\\x[0-9a-f]{2}|[A-Za-z0-9+/]{180,}={0,2})")


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    version: str
    weight: int
    signal: str


def _name(context: dict) -> str:
    return PurePosixPath(str(context.get("executable") or context.get("path") or context.get("name") or "")).name.lower()


def evaluate(event: TelemetryEvent) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    process_name = _name(event.process)
    parent_name = _name(event.parent_process)
    command = str(event.process.get("command_line", ""))
    path = str(event.process.get("executable") or event.process.get("path") or "")
    network_facing = bool(event.service_context.get("network_facing") or event.network_context.get("inbound"))
    service_parent = parent_name in SERVICE_NAMES or bool(event.parent_process.get("is_service"))

    if process_name in UNEXPECTED_UTILITIES and (network_facing or service_parent):
        matches.append(RuleMatch("RCE-EXEC-001", "1.0", 80, "network-facing service spawned an unexpected interpreter or utility"))
    if event.network_context.get("inbound") and event.kind in {"process_start", "execution"}:
        matches.append(RuleMatch("RCE-NET-001", "1.0", 55, "process execution followed a correlated inbound network event"))
    if event.file_context.get("written_by_service") and event.file_context.get("executed_after_write"):
        matches.append(RuleMatch("RCE-FILE-001", "1.0", 85, "service-written file was executed shortly after creation"))
    if path and any(marker.lower() in path.lower() for marker in RISK_PATHS):
        matches.append(RuleMatch("RCE-PATH-001", "1.0", 35, "execution occurred from a temporary, upload, cache, web-root, or shared writable path"))
    if process_name in INTERPRETERS and (len(command) > 512 or OBFUSCATION.search(command)):
        matches.append(RuleMatch("RCE-SCRIPT-001", "1.0", 50, "interpreter invocation contained encoded, obfuscated, or unusually long content"))
    if event.network_context.get("recent_inbound") and event.network_context.get("unexpected_outbound"):
        matches.append(RuleMatch("RCE-NET-002", "1.0", 55, "service initiated unexpected outbound traffic shortly after inbound traffic"))
    if event.memory_context.get("writable_to_executable"):
        matches.append(RuleMatch("RCE-MEM-001", "1.0", 80, "writable memory became executable"))
    if event.memory_context.get("cross_process_execution"):
        matches.append(RuleMatch("RCE-MEM-002", "1.0", 85, "cross-process execution behavior was observed"))
    injection_signals = {str(item).strip() for item in event.memory_context.get("injection_signals", []) if str(item).strip()}
    if injection_signals:
        weight = 60 if len(injection_signals) >= 2 else 30
        matches.append(RuleMatch("RCE-MEM-003", "1.0", weight, "macOS process-manipulation, loader, memory, or thread-state signals require injection review"))
    if event.service_context.get("restart_after_crash") and process_name in UNEXPECTED_UTILITIES:
        matches.append(RuleMatch("RCE-CRASH-001", "1.0", 60, "service restart after a crash was followed by an unusual child process"))
    if event.memory_context.get("memory_safety_crash"):
        matches.append(RuleMatch("RCE-MEMORY-SAFETY-001", "1.0", 55, "Apple crash diagnostics recorded a memory-safety failure requiring incident review"))
    if event.metadata.get("remote_administration"):
        matches.append(RuleMatch("RCE-REMOTE-ADMIN-001", "1.0", 30, "remote administration behavior resembles remote execution and requires review"))
    return matches

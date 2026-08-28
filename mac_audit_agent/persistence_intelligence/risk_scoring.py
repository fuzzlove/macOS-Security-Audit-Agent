from __future__ import annotations

import re
from pathlib import Path

from mac_audit_agent.persistence_intelligence.models import PersistenceFinding, PersistenceItem


SUSPICIOUS_COMMAND_RE = re.compile(r"\b(curl|wget|bash|sh|python|python3|perl|ruby|osascript|nc|ncat|base64|openssl|chmod|chflags)\b", re.IGNORECASE)
REMOTE_URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)
TEMP_PATH_MARKERS = ["/tmp", "/var/tmp", "/private/tmp", "/Users/Shared"]


def risk_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def score_item(item: PersistenceItem) -> PersistenceItem:
    score = 0
    factors: list[str] = []
    target = item.executable_path or item.program or item.path
    args = " ".join(item.program_arguments)
    combined = f"{target} {args}"
    mechanism_weight = {
        "dylib_insert": (55, "dynamic loader library insertion declaration"),
        "login_hook": (35, "login hook executes during user session startup"),
        "logout_hook": (30, "logout hook executes during session teardown"),
        "event_rule": (35, "event rule can execute commands automatically"),
        "startup_script": (30, "legacy operating-system startup script present"),
        "directory_services_plugin": (25, "Directory Services loads this plugin bundle"),
        "spotlight_importer": (18, "Spotlight worker loads this importer bundle"),
        "quicklook_plugin": (18, "Quick Look loads this generator bundle"),
        "dock_tile_plugin": (18, "Dock service loads this application plugin"),
        "embedded_login_helper": (20, "application contains an embedded login helper"),
        "ssh_authorized_key": (55, "SSH authorized key can provide durable remote account access"),
        "ssh_configuration": (20, "SSH configuration can redirect or weaken trusted remote access"),
        "applescript_persistence": (30, "AppleScript automation can execute commands without an interactive shell"),
        "application_bundle": (8, "application bundle is part of persistence provenance inventory"),
        "cron": (20, "cron job executes commands on a schedule or at reboot"),
        "periodic": (15, "periodic job executes automatically on a system schedule"),
    }.get(item.mechanism)
    if mechanism_weight:
        score += mechanism_weight[0]
        factors.append(mechanism_weight[1])
    if any(str(target).startswith(marker) or marker in str(target) for marker in TEMP_PATH_MARKERS):
        score += 30
        factors.append("target in temporary/shared writable path")
    if "/Downloads/" in str(target):
        score += 20
        factors.append("target in Downloads")
    if "/." in str(target):
        score += 12
        factors.append("target path includes hidden directory or file")
    if item.world_writable:
        score += 25
        factors.append("plist or target is world-writable")
    if any("removal-resistance flags" in value for value in item.evidence):
        score += 35
        factors.append("non-system persistence is marked immutable or append-only")
    if any("unreadable or malformed" in value for value in item.evidence):
        score += 40
        factors.append("non-system persistence could not be safely parsed")
    if item.writable_by_user and item.owner == "root":
        score += 25
        factors.append("root-owned persistence references user-writable target")
    if item.signed_status in {"unsigned", "invalid"}:
        score += 18 if item.signed_status == "unsigned" else 30
        factors.append(f"target signature is {item.signed_status}")
    if not item.target_exists and (item.program or item.executable_path):
        score += 18
        factors.append("target executable is missing")
    if item.run_at_load:
        score += 8
        factors.append("RunAtLoad enabled")
    if item.keep_alive:
        score += 12
        factors.append("KeepAlive enabled")
    if item.run_at_load and item.keep_alive:
        score += 10
        factors.append("RunAtLoad and KeepAlive both enabled")
    if item.label.startswith("com.apple.") and not str(item.plist_path or item.path).startswith(("/System/Library", "/Library/Apple")):
        score += 30
        factors.append("label mimics Apple outside protected Apple path")
    if SUSPICIOUS_COMMAND_RE.search(combined):
        score += 22
        factors.append("command invokes scripting/networking or obfuscation-capable tool")
    if REMOTE_URL_RE.search(combined):
        score += 25
        factors.append("command contains remote URL")
    if SUSPICIOUS_COMMAND_RE.search(combined) and REMOTE_URL_RE.search(combined):
        score += 25
        factors.append("network retrieval is combined with an execution-capable command")
    if item.mechanism == "launch_daemon" and item.signed_status in {"unsigned", "invalid"}:
        score += 35
        factors.append("unsigned or invalid LaunchDaemon can execute with system privileges")
    if item.mechanism == "ssh_authorized_key" and item.baseline_status in {"new", "changed"}:
        score += 35
        factors.append("SSH key is new or changed compared with the approved baseline")
    if item.baseline_status == "new":
        score += 18
        factors.append("new compared to baseline")
    if item.baseline_status in {"changed", "modified", "hash_changed"}:
        score += 22
        factors.append("changed compared to baseline")
    if "homebrew" in str(target).lower() and item.signed_status == "unsigned" and score < 40:
        factors.append("Homebrew path is unsigned but otherwise expected; not escalated solely for signature")
    item.risk_score = min(100, score)
    item.risk_level = risk_level(item.risk_score)
    item.evidence = [*item.evidence, *factors]
    item.recommended_verification = item.recommended_verification or "Confirm business purpose, target binary, signature, owner, permissions, and baseline history."
    return item


def findings_for_item(item: PersistenceItem) -> list[PersistenceFinding]:
    target_is_satisfied = item.target_exists or not (item.program or item.executable_path)
    if item.risk_level in {"INFO", "LOW"} and target_is_satisfied and not item.world_writable:
        return []
    title = f"{item.risk_level}: Review {item.mechanism.replace('_', ' ')} persistence item"
    description = f"{item.label or Path(item.path).name or item.mechanism} scored {item.risk_score}/100 for persistence risk."
    return [PersistenceFinding.from_item(item, title, description)]

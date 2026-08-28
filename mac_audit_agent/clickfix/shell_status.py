from __future__ import annotations

import hashlib
import json
import os
import pwd
from datetime import datetime, timezone
from pathlib import Path

from .shell_config import load_config


BEGIN = "# >>> MSAA CLICKFIX GUARD MANAGED BLOCK >>>"
REQUIRED_FILES = ("msaa-clickfix-scan", "msaa-clickfix-adapter", "msaa-safe-shell", "msaa-clickfix.zsh", "msaa-clickfix.bash")


def default_shell_guard_prefix() -> Path:
    return Path.home() / ".local/lib/msaa-clickfix"


def _managed(path: Path) -> bool:
    try: return BEGIN in path.read_text(encoding="utf-8")
    except OSError: return False


def _manifest_valid(prefix: Path) -> bool:
    try:
        expected = {}
        for line in (prefix / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ", 1)
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or not name:
                return False
            expected[name] = digest
        if not set(REQUIRED_FILES).issubset(expected):
            return False
        return all((prefix / name).is_file() and hashlib.sha256((prefix / name).read_bytes()).hexdigest() == digest for name, digest in expected.items())
    except (OSError, ValueError):
        return False


def _latest_event(path: Path) -> tuple[str | None, str | None, int]:
    try:
        if path.stat().st_size > 32 * 1024 * 1024: return None, "event_log_oversized", 0
        lines = path.read_bytes().splitlines()[-200:]
    except OSError: return None, None, 0
    valid = []
    for line in lines:
        try:
            payload = json.loads(line)
            if isinstance(payload, dict) and payload.get("schema") == "msaa.clickfix.event.v1": valid.append(payload)
        except (ValueError, TypeError): continue
    if not valid: return None, "no_valid_events" if lines else None, 0
    return str(valid[-1].get("timestamp") or ""), str(valid[-1].get("event_type") or ""), len(valid)


def shell_guard_status(*, home: Path | None = None, prefix: Path | None = None, event_log: Path | None = None) -> dict[str, object]:
    selected_home = (home or Path.home()).resolve(); selected_prefix = (prefix or (selected_home / ".local/lib/msaa-clickfix")).resolve()
    installed = all((selected_prefix / name).is_file() for name in REQUIRED_FILES)
    zsh = _managed(selected_home / ".zshrc")
    bashrc = _managed(selected_home / ".bashrc"); bash_profile = _managed(selected_home / ".bash_profile")
    manifest = _manifest_valid(selected_prefix) if installed else False
    try: login_shell = pwd.getpwuid(os.getuid()).pw_shell or "unknown"
    except KeyError: login_shell = "unknown"
    config_error = ""
    try:
        config = load_config(user_path=selected_home / "Library/Preferences/com.msaa.clickfix.plist")
        mode = config.mode
        source = config.source
        proxy_enabled = config.generic_proxy_enabled
    except ValueError as exc: mode = "unavailable"; source = "invalid"; proxy_enabled = False; config_error = type(exc).__name__
    latest_at, latest_type, sample_count = _latest_event(event_log or (selected_home / "Library/Logs/MSAA/clickfix-events.jsonl"))
    age_seconds = None
    if latest_at:
        try: age_seconds = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(latest_at.replace("Z", "+00:00"))).total_seconds()))
        except ValueError: pass
    shell_name = Path(login_shell).name
    direct_coverage = zsh if shell_name == "zsh" else (bashrc or bash_profile) if shell_name == "bash" else False
    proxy_available = installed and os.access(selected_prefix / "msaa-safe-shell", os.X_OK)
    if direct_coverage:
        coverage = "direct_shell_adapter"
    elif proxy_enabled and proxy_available:
        coverage = "degraded_proxy_available_opt_in_unverified"
    else:
        coverage = "degraded_uninstrumented_login_shell"
    # A preference cannot prove that a terminal actually starts through the PTY
    # proxy. Only a startup block for the active login shell is locally verifiable.
    operational = installed and manifest and direct_coverage and not config_error
    return {
        "schema_version":"1.0", "primary_interim_control":"shell_guard", "installed":installed, "manifest_valid":manifest,
        "prefix":str(selected_prefix), "login_shell":login_shell, "zsh_adapter_configured":zsh, "bashrc_adapter_configured":bashrc,
        "bash_profile_adapter_configured":bash_profile, "generic_proxy_available":proxy_available, "generic_proxy_enabled":proxy_enabled,
        "mode":mode, "configuration_source":source, "configuration_error":config_error, "coverage_level":coverage,
        "warn_threshold":getattr(config,"warn_threshold",4) if not config_error else None,
        "block_threshold":getattr(config,"block_threshold",7) if not config_error else None,
        "operational":operational, "last_event_at":latest_at, "last_event_type":latest_type, "recent_valid_event_sample_count":sample_count,
        "last_event_age_seconds":age_seconds, "raw_command_logged":False, "endpoint_security_required":False,
        "limitations":["Shell startup files can be bypassed or changed.","Noninteractive and GUI-launched execution may bypass adapters.","Other shells require explicit msaa-safe-shell opt-in.","No recent event is not proof that no malicious paste occurred."],
    }


__all__ = ["default_shell_guard_prefix", "shell_guard_status"]

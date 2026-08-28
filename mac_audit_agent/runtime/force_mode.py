from __future__ import annotations

import getpass
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from mac_audit_agent.models import utc_now_iso


SAFE_FORCE_SCOPES = {
    "refresh",
    "rescan",
    "repair",
    "restart",
    "reinstall",
    "rebuild_cache",
    "rebuild_manifest",
    "diagnostics",
}
UNSAFE_FORCE_SCOPES = {
    "trust",
    "delete_evidence",
    "delete_logs",
    "delete_database",
    "disable_security_control",
    "suppress_alerts",
    "external_scan",
    "destructive_remediation",
}


@dataclass
class ForceMode:
    enabled: bool = False
    source: str = "cli_flag"
    scope: str = "unsupported"
    confirmation_required: bool = False
    destructive_allowed: bool = False
    bypass_integrity_allowed: bool = False
    bypass_safety_allowed: bool = False
    reason: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ForceArgumentError(ValueError):
    pass


def strip_force_tokens(argv: Iterable[str]) -> tuple[list[str], bool | None, str]:
    cleaned: list[str] = []
    force_value: bool | None = None
    source = "cli_flag"
    skip_next = False
    for token in list(argv):
        if skip_next:
            skip_next = False
            continue
        lowered = str(token).strip().lower()
        if lowered in {"--force", "-f", "force"}:
            force_value = True
            source = "cli_keyword" if lowered == "force" else "cli_flag"
            continue
        if lowered in {"--no-force", "force=false", "--force=false", "-f=false"}:
            force_value = False
            source = "cli_flag"
            continue
        if lowered in {"force=true", "--force=true", "-f=true"}:
            force_value = True
            source = "cli_flag"
            continue
        if lowered == "--force" and token != lowered:
            force_value = True
            continue
        cleaned.append(str(token))
    return cleaned, force_value, source


def infer_force_scope(command: str, argv: Iterable[str] = ()) -> str:
    text = " ".join([command, *[str(item) for item in argv]]).lower()
    if any(word in text for word in ("delete evidence", "delete-evidence", "delete logs", "delete database", "disable sip", "disable gatekeeper", "suppress alert", "external scan")):
        return "delete_evidence" if "evidence" in text else "suppress_alerts" if "alert" in text else "external_scan" if "external" in text else "disable_security_control"
    if any(word in text for word in ("trust", "rebaseline", "baseline update")) and "verify" not in text:
        return "trust"
    if any(word in text for word in ("repair", "doctor")):
        return "repair"
    if any(word in text for word in ("restart", "kickstart")):
        return "restart"
    if any(word in text for word in ("reinstall", "bootstrap")):
        return "reinstall"
    if any(word in text for word in ("manifest", "sign")):
        return "rebuild_manifest"
    if any(word in text for word in ("verify", "diagnostic", "doctor", "pre_uat", "pre-uat")):
        return "diagnostics"
    if any(word in text for word in ("scan", "rescan", "rootkit", "persistence")):
        return "rescan"
    if any(word in text for word in ("refresh", "report", "export")):
        return "refresh"
    return "unsupported"


def parse_force_argument(
    argv: Iterable[str],
    *,
    command: str = "",
    supported_scopes: set[str] | None = None,
    default_scope: str | None = None,
    require_command: bool = True,
) -> tuple[list[str], ForceMode]:
    cleaned, value, source = strip_force_tokens(argv)
    scope = default_scope or infer_force_scope(command, cleaned)
    mode = ForceMode(
        enabled=bool(value),
        source=source,
        scope=scope,
        confirmation_required=scope in {"repair", "restart", "reinstall", "rebuild_manifest"} and bool(value),
        reason="Force enabled: cached data will be bypassed and the operation will run fresh." if value else "",
    )
    if value is None:
        return cleaned, mode
    if require_command and not command and not cleaned:
        raise ForceArgumentError("Specify what to force. Examples: scan --force, refresh --force, repair-notifier --force.")
    if scope in UNSAFE_FORCE_SCOPES:
        mode.enabled = False
        mode.warnings.append("Force was refused because this action could alter security state or evidence.")
        raise ForceArgumentError("Force was refused because this action could alter security state or evidence.")
    allowed = supported_scopes or SAFE_FORCE_SCOPES
    if scope not in allowed:
        mode.enabled = False
        mode.warnings.append("Force is not supported for this command.")
        raise ForceArgumentError("Force is not supported for this command. Use --force only with refresh, scan, repair, restart, or diagnostics commands.")
    mode.destructive_allowed = False
    mode.bypass_safety_allowed = False
    mode.bypass_integrity_allowed = False
    mode.warnings.extend(
        [
            "Force does not bypass integrity verification.",
            "Force does not bypass safety checks or confirmations.",
            "Force does not delete evidence or suppress alerts.",
        ]
    )
    return cleaned, mode


def default_force_log_path() -> Path:
    override = os.environ.get("MSAA_FORCE_LOG_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Logs" / "MacAuditAgent" / "actions.log"


def log_force_action(command: str, mode: ForceMode, *, action_taken: str = "", result: str = "", error: str = "", log_path: Path | None = None) -> Path:
    path = log_path or default_force_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": utc_now_iso(),
        "user": getpass.getuser(),
        "command": command,
        "force_enabled": mode.enabled,
        "force_scope": mode.scope,
        "reason": mode.reason,
        "action_taken": action_taken,
        "safety_checks_passed": not mode.destructive_allowed and not mode.bypass_safety_allowed and not mode.bypass_integrity_allowed,
        "result": result,
        "error": error,
        "warnings": list(mode.warnings),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return path


def force_diagnostics(log_path: Path | None = None) -> dict[str, object]:
    path = log_path or default_force_log_path()
    entries: list[dict[str, object]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-50:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rejected = [entry for entry in entries if entry.get("error")]
    return {
        "last_force_action": entries[-1] if entries else {},
        "force_supported_commands": sorted(SAFE_FORCE_SCOPES),
        "rejected_force_actions": rejected[-10:],
        "last_force_rejection_reason": str(rejected[-1].get("error", "")) if rejected else "",
        "log_path": str(path),
    }


__all__ = [
    "ForceArgumentError",
    "ForceMode",
    "SAFE_FORCE_SCOPES",
    "UNSAFE_FORCE_SCOPES",
    "force_diagnostics",
    "infer_force_scope",
    "log_force_action",
    "parse_force_argument",
    "strip_force_tokens",
]

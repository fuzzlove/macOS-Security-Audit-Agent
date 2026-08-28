from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.models import BackgroundMonitorStatus


@dataclass
class MockLaunchAgent:
    """Read-only LaunchAgent fixture for UI layout audits."""

    db_path: str | Path = "/private/tmp/msaa-ui-audit.sqlite3"
    scope: str = "user"
    label: str = "com.mac-audit-agent.audit-fixture"
    plist_path: str | Path = "/private/tmp/com.mac-audit-agent.audit-fixture.plist"
    log_path: str | Path = "/private/tmp/com.mac-audit-agent.audit-fixture.log"
    loaded: bool = False
    running: bool = False
    status_text: str = "audit fixture"

    def __post_init__(self) -> None:
        self.db_path = str(self.db_path)
        self.plist_path = str(self.plist_path)
        self.log_path = str(self.log_path)
        self.paths = SimpleNamespace(
            plist_path=Path(self.plist_path),
            stdout_path=Path(self.log_path),
            stderr_path=Path(str(self.log_path) + ".err"),
        )

    def status(self) -> BackgroundMonitorStatus:
        return BackgroundMonitorStatus(
            installed=True,
            loaded=self.loaded,
            running=self.running,
            enabled=True,
            plist_path=self.plist_path,
            label=self.label,
            log_path=self.log_path,
            db_path=self.db_path,
            current_launchctl_domain=f"gui/audit" if self.scope == "user" else self.scope,
            status_text=self.status_text,
        )

    def show_logs(self) -> str:
        return self.log_path

    def verify_protected_monitor_integrity(self) -> dict[str, object]:
        return {
            "tamper_detected": False,
            "protected_mode": self.scope == "system",
            "evidence": ["UI audit fixture only; no launchctl calls performed."],
            "severity": "info",
        }

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def restart(self) -> None:
        return None

    def install(self, *args: object, **kwargs: object) -> Path:
        return Path(self.plist_path)

    def repair(self, *args: object, **kwargs: object) -> tuple[Path, list[str]]:
        return Path(self.plist_path), ["UI audit fixture repair skipped."]

    def uninstall(self, *args: object, **kwargs: object) -> None:
        return None

    def install_user_notifier(self, *args: object, **kwargs: object) -> Path:
        return Path(self.plist_path)

    def install_system_monitor(self, *args: object, **kwargs: object) -> Path:
        return Path(self.plist_path)

    def install_protected_mode(self, *args: object, **kwargs: object) -> Path:
        return Path(self.plist_path)

    def uninstall_protected_mode(self, *args: object, **kwargs: object) -> None:
        return None

    def revert_to_user_mode(self, *args: object, **kwargs: object) -> Path:
        return Path(self.plist_path)

    def lock_down_protected_files(self) -> list[str]:
        return ["UI audit fixture lock-down skipped."]


__all__ = ["MockLaunchAgent"]

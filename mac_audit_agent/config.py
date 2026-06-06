from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONCERNING_PORTS = {
    21: "FTP is rarely needed on endpoints and increases exposure if enabled unexpectedly.",
    22: "SSH may be legitimate, but unexpected exposure can permit remote administration attempts.",
    23: "Telnet is legacy and insecure because traffic is not encrypted.",
    25: "SMTP on an endpoint can indicate relay, testing, or malware staging.",
    53: "DNS listeners are uncommon on workstations and merit validation.",
    80: "HTTP listeners may expose local apps or admin panels unintentionally.",
    111: "RPC services are uncommon on endpoints and widen attack surface.",
    135: "MSRPC is unusual on macOS and may indicate compatibility tooling.",
    139: "NetBIOS/SMB legacy exposure can broaden network attack surface.",
    445: "SMB listeners should be reviewed to confirm intentional file sharing.",
    513: "rlogin is legacy and insecure.",
    514: "rsh is legacy and insecure.",
    1080: "SOCKS proxy listeners can indicate tunneling or proxy tooling.",
    1433: "MSSQL listeners are uncommon on endpoints and may expose databases.",
    1521: "Oracle listeners are uncommon on endpoints and may expose databases.",
    2049: "NFS listeners should be reviewed for unnecessary file sharing.",
    2375: "Unauthenticated Docker API exposure is high risk.",
    3306: "MySQL listeners may expose a local or test database.",
    3389: "RDP on macOS is uncommon and may indicate virtualization or compatibility layers.",
    4444: "Port 4444 is commonly used in malware and reverse-shell examples.",
    5000: "Development services often bind here and may expose debug features.",
    5001: "Development or alternate service port that may expose admin or test interfaces.",
    5432: "PostgreSQL listeners may expose a local or test database.",
    5900: "VNC enables remote screen access and should be intentionally enabled.",
    5985: "WinRM is uncommon on macOS and suggests compatibility tooling.",
    5986: "WinRM over TLS is uncommon on macOS and suggests compatibility tooling.",
    6379: "Redis should not usually be exposed on a workstation.",
    8000: "Common dev web service port that may expose test interfaces.",
    8080: "Common proxy/dev service port that may expose admin interfaces.",
    8888: "Often used by notebooks and web proxies that may expose local data or control surfaces.",
    9001: "Used by proxy and Tor-related tooling; validate whether it is expected.",
    9200: "Elasticsearch exposure has a history of accidental data exposure.",
    11211: "Memcached should rarely be exposed on a workstation.",
    27017: "MongoDB exposure should be reviewed carefully.",
}


@dataclass
class AuditConfig:
    logs_dir: Path = field(default_factory=lambda: Path.home() / ".mac_audit_agent" / "logs")
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".mac_audit_agent" / "cache")
    log_retention_days: int = 30
    dry_run: bool = False
    fresh_baseline_validation_mode: bool = False
    uat_live_environment_mode: bool = False
    disable_packet_capture: bool = False
    disable_aggressive_scan: bool = False
    allow_system_modifications: bool = False
    auto_update_apple_security_forecast: bool = False
    update_interval_hours: int = 6
    show_review_needed_apple_cves: bool = False
    include_apple_ecosystem_advisories: bool = False
    developer_mode: bool = False
    include_history_context: bool = False
    recovery_snapshot_dir: Path = field(default_factory=lambda: Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "snapshots")
    cleanup_crash_log_age_days: int = 30
    recovery_scan_timeout_seconds: int = 10
    recovery_cleanup_exclusions: list[str] = field(default_factory=list)
    redact_usernames: bool = True
    redact_paths: bool = True
    redact_ips: bool = True
    redact_hostnames: bool = True
    redact_macs: bool = True
    redact_url_secrets: bool = True
    concerning_ports: dict[int, str] = field(default_factory=lambda: dict(DEFAULT_CONCERNING_PORTS))

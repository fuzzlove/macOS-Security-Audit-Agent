from __future__ import annotations

import hashlib
import json
import os
import plistlib
import pwd
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.persistence_intelligence.coverage import coverage_from_results
from mac_audit_agent.persistence_intelligence.malware_kb import correlate_item
from mac_audit_agent.persistence_intelligence.mitre_mapping import mitre_for_mechanism
from mac_audit_agent.persistence_intelligence.models import PersistenceItem, PersistenceScanReport, ScannerResult
from mac_audit_agent.persistence_intelligence.risk_scoring import findings_for_item, score_item
from mac_audit_agent.persistence_intelligence.trust_reputation import score_trust


@dataclass
class ScanContext:
    home: Path = Path.home()
    system_root: Path = Path("/")
    include_downloads: bool = False
    max_support_files: int = 250


class PersistenceScanner:
    scanner_id = "base"
    name = "Base Scanner"
    description = ""
    requires_full_disk_access = False
    requires_root = False
    supported_macos_versions = ["macOS"]

    def scan(self, context: ScanContext) -> ScannerResult:
        raise NotImplementedError

    def _result(self, started: float, items: list[PersistenceItem], warnings: list[str] | None = None, errors: list[str] | None = None) -> ScannerResult:
        findings = []
        for item in items:
            item.source_scanner = item.source_scanner or self.scanner_id
            item.mitre_techniques = item.mitre_techniques or mitre_for_mechanism(item.mechanism)
            score_trust(item)
            score_item(item)
            for match in correlate_item(item):
                item.evidence.append(
                    f"Artifact resembles public persistence pattern associated with {match['malware_family']}. Review recommended."
                )
                item.confidence = "medium"
            findings.extend(findings_for_item(item))
        status = "partial" if warnings else ("failed" if errors else "healthy")
        return ScannerResult(
            scanner_id=self.scanner_id,
            items=items,
            findings=findings,
            warnings=warnings or [],
            errors=errors or [],
            duration_ms=int((time.monotonic() - started) * 1000),
            coverage_status=status,
        )


def _safe_iter(paths: Iterable[Path], suffix: str = "") -> tuple[list[Path], list[str]]:
    found: list[Path] = []
    warnings: list[str] = []
    for root in paths:
        try:
            if not root.exists():
                continue
            iterator = root.glob(f"*{suffix}") if suffix else root.iterdir()
            found.extend(path for path in iterator if path.exists())
        except PermissionError:
            warnings.append(f"Unreadable path due to permission restrictions: {root}. Full Disk Access may improve coverage.")
        except OSError as exc:
            warnings.append(f"Unable to inspect {root}: {exc}")
    return found, warnings


def _stat_fields(path: Path) -> dict:
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = str(st.st_gid)
        return {
            "owner": owner,
            "group": group,
            "permissions": oct(mode),
            "world_writable": bool(mode & stat.S_IWOTH),
            "writable_by_user": os.access(path, os.W_OK),
        }
    except Exception:
        return {"owner": "", "group": "", "permissions": "", "world_writable": False, "writable_by_user": False}


def _hash_file(path: Path, max_bytes: int = 25_000_000) -> str:
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return ""
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _target_from_args(program: str, args: list[str]) -> str:
    if program:
        return program
    if args:
        return args[0]
    return ""


def _item_from_path(mechanism: str, path: Path, *, label: str = "", program: str = "", args: list[str] | None = None, scanner_id: str = "") -> PersistenceItem:
    target = _target_from_args(program, args or [])
    target_path = Path(target).expanduser() if target and target.startswith(("/", "~")) else Path("")
    fields = _stat_fields(path)
    target_exists = bool(target_path and target_path.exists())
    return PersistenceItem.create(
        mechanism,
        str(path),
        label=label,
        plist_path=str(path) if path.suffix == ".plist" else "",
        executable_path=str(target_path) if target else "",
        program=program,
        program_arguments=args or [],
        target_exists=target_exists,
        target_hash_sha256=_hash_file(target_path) if target_exists else "",
        signed_status="unknown",
        source_scanner=scanner_id,
        evidence=[f"Observed {mechanism} source: {path}"],
        **fields,
    )


class LaunchdScanner(PersistenceScanner):
    scanner_id = "launchd"
    name = "Launchd Scanner"
    description = "LaunchAgents and LaunchDaemons plist inventory."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [
            context.home / "Library" / "LaunchAgents",
            context.system_root / "Library" / "LaunchAgents",
            context.system_root / "System" / "Library" / "LaunchAgents",
            context.system_root / "Library" / "LaunchDaemons",
            context.system_root / "System" / "Library" / "LaunchDaemons",
        ]
        plists, warnings = _safe_iter(roots, ".plist")
        items: list[PersistenceItem] = []
        errors: list[str] = []
        for plist in plists:
            try:
                payload = plistlib.loads(plist.read_bytes())
                label = str(payload.get("Label") or plist.stem)
                args = [str(item) for item in payload.get("ProgramArguments", [])] if isinstance(payload.get("ProgramArguments", []), list) else []
                program = str(payload.get("Program") or "")
                mechanism = "launch_daemon" if "LaunchDaemons" in str(plist) else "launch_agent"
                item = _item_from_path(mechanism, plist, label=label, program=program, args=args, scanner_id=self.scanner_id)
                item.run_at_load = bool(payload.get("RunAtLoad", False))
                item.keep_alive = bool(payload.get("KeepAlive", False))
                item.disabled = bool(payload.get("Disabled", False))
                items.append(item)
            except Exception as exc:
                errors.append(f"Failed to parse plist {plist}: {exc}")
        return self._result(started, items, warnings, errors)


class BackgroundItemsScanner(PersistenceScanner):
    scanner_id = "background_items"
    name = "Background Items Scanner"
    description = "Login items, Background Task Management, and session restore indicators."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [
            context.home / "Library" / "Application Support" / "com.apple.backgroundtaskmanagementagent",
            context.home / "Library" / "Preferences" / "ByHost",
            context.home / "Library" / "Saved Application State",
        ]
        paths, warnings = _safe_iter(roots)
        items = [_item_from_path("background_item", path, label=path.name, scanner_id=self.scanner_id) for path in paths[:200]]
        return self._result(started, items, warnings)


class ScheduledJobsScanner(PersistenceScanner):
    scanner_id = "scheduled_jobs"
    name = "Scheduled Jobs Scanner"
    description = "Cron, at, periodic, and script directory inventory."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [Path("/etc/periodic"), Path("/usr/local/etc/periodic"), Path("/Library/Scripts"), Path("/var/at/tabs"), Path("/usr/lib/cron/tabs")]
        paths, warnings = _safe_iter(roots)
        for file in [context.home / ".crontab", Path("/etc/crontab")]:
            if file.exists():
                paths.append(file)
        items = [_item_from_path("periodic" if "periodic" in str(path) else "cron", path, label=path.name, scanner_id=self.scanner_id) for path in paths[:300]]
        return self._result(started, items, warnings)


class ShellStartupScanner(PersistenceScanner):
    scanner_id = "shell_startup"
    name = "Shell Startup Scanner"
    description = "Shell startup file indicators without storing shell history."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        files = [
            context.home / ".zshrc",
            context.home / ".zprofile",
            context.home / ".zlogin",
            context.home / ".bash_profile",
            context.home / ".bashrc",
            context.home / ".profile",
            Path("/etc/zshrc"),
            Path("/etc/bashrc"),
            Path("/etc/profile"),
        ]
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        for file in files:
            if not file.exists():
                continue
            item = _item_from_path("shell_startup", file, label=file.name, scanner_id=self.scanner_id)
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
                redacted = "\n".join(line for line in text.splitlines() if any(token in line.lower() for token in ["curl", "wget", "osascript", "launchctl", "python", "bash", "nc "]))[:1000]
                if redacted:
                    item.program_arguments = [redacted]
                    item.evidence.append("Shell startup file contains command patterns requiring review; secrets and full history are not stored.")
            except PermissionError:
                warnings.append(f"Unreadable shell startup file: {file}")
            items.append(item)
        return self._result(started, items, warnings)


class AuthorizationPluginScanner(PersistenceScanner):
    scanner_id = "authorization_plugins"
    name = "Authorization Plugin Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        paths, warnings = _safe_iter([Path("/Library/Security/SecurityAgentPlugins"), Path("/System/Library/Security/SecurityAgentPlugins")])
        return self._result(started, [_item_from_path("authorization_plugin", path, label=path.name, scanner_id=self.scanner_id) for path in paths], warnings)


class BrowserPersistenceScanner(PersistenceScanner):
    scanner_id = "browser_extensions"
    name = "Browser Persistence Scanner"
    description = "Browser extensions and native messaging hosts; does not inspect browsing history or cookies."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [
            context.home / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts",
            context.home / "Library" / "Application Support" / "Chromium" / "NativeMessagingHosts",
            context.home / "Library" / "Application Support" / "Microsoft Edge" / "NativeMessagingHosts",
            context.home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "NativeMessagingHosts",
            context.home / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts",
            Path("/Library/Google/Chrome/NativeMessagingHosts"),
            Path("/Library/Application Support/Mozilla/NativeMessagingHosts"),
        ]
        paths, warnings = _safe_iter(roots)
        items: list[PersistenceItem] = []
        for path in paths:
            program = ""
            args: list[str] = []
            if path.suffix == ".json":
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    program = str(payload.get("path") or "")
                    args = [program] if program else []
                except Exception as exc:
                    warnings.append(f"Unable to parse native messaging host {path}: {exc}")
            items.append(_item_from_path("native_messaging_host", path, label=path.stem, program=program, args=args, scanner_id=self.scanner_id))
        extension_roots = [
            context.home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Extensions",
            context.home / "Library" / "Application Support" / "Chromium" / "Default" / "Extensions",
            context.home / "Library" / "Application Support" / "Firefox" / "Profiles",
            context.home / "Library" / "Safari" / "Extensions",
        ]
        ext_paths, ext_warnings = _safe_iter(extension_roots)
        warnings.extend(ext_warnings)
        items.extend(_item_from_path("browser_extension", path, label=path.name, scanner_id=self.scanner_id) for path in ext_paths[:300])
        return self._result(started, items, warnings)


class ProfileAndManagedPreferencesScanner(PersistenceScanner):
    scanner_id = "profiles_managed_preferences"
    name = "Profiles and Managed Preferences Scanner"
    requires_full_disk_access = True

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        paths, warnings = _safe_iter([Path("/Library/Managed Preferences"), Path("/var/db/ConfigurationProfiles")])
        return self._result(started, [_item_from_path("configuration_profile", path, label=path.name, scanner_id=self.scanner_id) for path in paths[:300]], warnings)


class CertificateTrustScanner(PersistenceScanner):
    scanner_id = "certificate_trust"
    name = "Certificate Trust Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [context.home / "Library" / "Keychains", Path("/Library/Keychains"), Path("/System/Library/Keychains")]
        paths, warnings = _safe_iter(roots)
        return self._result(started, [_item_from_path("certificate_trust", path, label=path.name, scanner_id=self.scanner_id) for path in paths[:200]], warnings)


class ExtensionInventoryScanner(PersistenceScanner):
    scanner_id = "extension_inventory"
    name = "Extension Inventory Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        paths, warnings = _safe_iter([Path("/Library/SystemExtensions"), Path("/Library/Extensions"), context.home / "Library" / "SystemExtensions"])
        return self._result(started, [_item_from_path("system_extension", path, label=path.name, scanner_id=self.scanner_id) for path in paths[:300]], warnings)


class PrivilegedHelperScanner(PersistenceScanner):
    scanner_id = "privileged_helpers"
    name = "Privileged Helper Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        paths, warnings = _safe_iter([Path("/Library/PrivilegedHelperTools")])
        return self._result(started, [_item_from_path("privileged_helper", path, label=path.name, program=str(path), args=[str(path)], scanner_id=self.scanner_id) for path in paths], warnings)


class PathHijackScanner(PersistenceScanner):
    scanner_id = "path_hijack"
    name = "PATH Hijack Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        dirs = [Path(part).expanduser() for part in os.environ.get("PATH", "").split(":") if part]
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        for directory in dirs:
            if not directory.exists():
                continue
            fields = _stat_fields(directory)
            if fields.get("world_writable") or fields.get("writable_by_user"):
                items.append(PersistenceItem.create("path_hijack", str(directory), label=directory.name, source_scanner=self.scanner_id, evidence=[f"Writable PATH directory: {directory}"], **fields))
            try:
                for name in ["sh", "bash", "curl", "sudo", "launchctl", "osascript"]:
                    candidate = directory / name
                    if candidate.exists() and not str(candidate).startswith(("/bin", "/usr/bin", "/usr/sbin", "/sbin")):
                        items.append(_item_from_path("path_hijack", candidate, label=name, program=str(candidate), scanner_id=self.scanner_id))
            except PermissionError:
                warnings.append(f"Unreadable PATH directory: {directory}")
        return self._result(started, items, warnings)


class SupportDirectoryScanner(PersistenceScanner):
    scanner_id = "support_directories"
    name = "Support Directory Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [
            context.home / "Library" / "Application Support",
            context.home / "Library" / "Containers",
            context.home / "Library" / "Group Containers",
            context.home / "Library" / "Preferences",
            Path("/Users/Shared"),
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/private/tmp"),
        ]
        if context.include_downloads:
            roots.append(context.home / "Downloads")
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        seen = 0
        for root in roots:
            try:
                if not root.exists():
                    continue
                for path in root.rglob("*"):
                    if seen >= context.max_support_files:
                        break
                    try:
                        if path.is_file() and os.access(path, os.X_OK):
                            hidden = any(part.startswith(".") for part in path.parts)
                            recent = time.time() - path.stat().st_mtime < 14 * 86400
                            if hidden or recent or root in {Path("/tmp"), Path("/var/tmp"), Path("/private/tmp"), Path("/Users/Shared")}:
                                items.append(_item_from_path("support_directory", path, label=path.name, program=str(path), scanner_id=self.scanner_id))
                                seen += 1
                    except OSError:
                        continue
            except PermissionError:
                warnings.append(f"Unreadable support path: {root}. Full Disk Access may improve coverage.")
        return self._result(started, items, warnings)


class UserGroupPersistenceScanner(PersistenceScanner):
    scanner_id = "user_group"
    name = "User and Group Persistence Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        items: list[PersistenceItem] = []
        for user in pwd.getpwall():
            if user.pw_uid >= 500 or user.pw_name == "root":
                home = Path(user.pw_dir)
                shell = user.pw_shell or ""
                evidence = [f"Local user {user.pw_name} uid={user.pw_uid} shell={shell}"]
                if shell and shell not in {"/bin/zsh", "/bin/bash", "/usr/bin/false", "/usr/sbin/nologin"}:
                    evidence.append("User has unusual login shell")
                ssh = home / ".ssh" / "authorized_keys"
                if ssh.exists():
                    evidence.append("authorized_keys present")
                items.append(PersistenceItem.create("user_group", str(home), label=user.pw_name, source_scanner=self.scanner_id, evidence=evidence))
        return self._result(started, items)


class TCCIndicatorScanner(PersistenceScanner):
    scanner_id = "tcc_indicators"
    name = "TCC Indicator Scanner"
    requires_full_disk_access = True

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [context.home / "Library" / "Application Support" / "com.apple.TCC", Path("/Library/Application Support/com.apple.TCC")]
        paths, warnings = _safe_iter(roots)
        if not paths:
            warnings.append("TCC indicators unavailable or unreadable. MSAA does not bypass TCC; grant Full Disk Access for broader visibility.")
        return self._result(started, [_item_from_path("tcc_indicator", path, label=path.name, scanner_id=self.scanner_id) for path in paths], warnings)


def scanner_registry() -> list[PersistenceScanner]:
    return [
        LaunchdScanner(),
        BackgroundItemsScanner(),
        ScheduledJobsScanner(),
        ShellStartupScanner(),
        AuthorizationPluginScanner(),
        BrowserPersistenceScanner(),
        ProfileAndManagedPreferencesScanner(),
        CertificateTrustScanner(),
        ExtensionInventoryScanner(),
        PrivilegedHelperScanner(),
        PathHijackScanner(),
        SupportDirectoryScanner(),
        UserGroupPersistenceScanner(),
        TCCIndicatorScanner(),
    ]


class PersistenceIntelligenceEngine:
    def __init__(self, context: ScanContext | None = None, scanners: list[PersistenceScanner] | None = None) -> None:
        self.context = context or ScanContext()
        self.scanners = scanners or scanner_registry()

    def scan(self, *, modules: list[str] | None = None) -> PersistenceScanReport:
        started_at = utc_now_iso()
        scan_id = f"persistence-{uuid4().hex[:12]}"
        requested = set(modules or [])
        results: list[ScannerResult] = []
        for scanner in self.scanners:
            if requested and scanner.scanner_id not in requested and scanner.name.lower().replace(" ", "_") not in requested:
                continue
            try:
                results.append(scanner.scan(self.context))
            except Exception as exc:
                results.append(ScannerResult(scanner.scanner_id, errors=[str(exc)], coverage_status="failed"))
        items = [item for result in results for item in result.items]
        findings = [finding for result in results for finding in result.findings]
        warnings = [warning for result in results for warning in result.warnings]
        errors = [error for result in results for error in result.errors]
        posture_score = max(0, 100 - min(100, sum(max(0, item.risk_score - 20) for item in items) // 5))
        return PersistenceScanReport(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=utc_now_iso(),
            items=items,
            findings=findings,
            scanner_results=results,
            posture_score=posture_score,
            coverage=coverage_from_results(results),
            warnings=warnings,
            errors=errors,
        )

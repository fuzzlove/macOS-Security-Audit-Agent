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
from mac_audit_agent.not_signed.signing_assessor import SigningAssessor
from mac_audit_agent.persistence_intelligence.trust_store import PersistenceTrustStore


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
        flags = getattr(st, "st_flags", 0)
        flag_names = [
            name for mask, name in (
                (getattr(stat, "UF_IMMUTABLE", 0), "user_immutable"),
                (getattr(stat, "UF_APPEND", 0), "user_append_only"),
                (getattr(stat, "SF_IMMUTABLE", 0), "system_immutable"),
                (getattr(stat, "SF_APPEND", 0), "system_append_only"),
            ) if mask and flags & mask
        ]
        return {
            "owner": owner,
            "group": group,
            "permissions": oct(mode),
            "world_writable": bool(mode & stat.S_IWOTH),
            "writable_by_user": os.access(path, os.W_OK),
            "persistence_flags": flag_names,
        }
    except Exception:
        return {"owner": "", "group": "", "permissions": "", "world_writable": False, "writable_by_user": False, "persistence_flags": []}


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


def _system_path(context: ScanContext, absolute_path: str) -> Path:
    """Map an absolute macOS path into a testable system root."""
    return context.system_root / absolute_path.lstrip("/")


def _read_plist(path: Path, warnings: list[str]) -> dict:
    try:
        payload = plistlib.loads(path.read_bytes())
        return payload if isinstance(payload, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
        warnings.append(f"Unable to parse plist {path}: {exc}")
        return {}


def _item_from_path(mechanism: str, path: Path, *, label: str = "", program: str = "", args: list[str] | None = None, scanner_id: str = "") -> PersistenceItem:
    target = _target_from_args(program, args or [])
    target_path = Path(target).expanduser() if target and target.startswith(("/", "~")) else None
    fields = _stat_fields(path)
    target_exists = bool(target_path is not None and target_path.exists())
    persistence_flags = fields.pop("persistence_flags", [])
    evidence = [f"Observed {mechanism} source: {path}"]
    warnings: list[str] = []
    if persistence_flags and not str(path).startswith("/System/Library/"):
        evidence.append("Non-system persistence artifact has removal-resistance flags: " + ", ".join(persistence_flags))
        warnings.append("Removal-resistant non-system persistence requires administrator or recovery review.")
    return PersistenceItem.create(
        mechanism,
        str(path),
        label=label,
        plist_path=str(path) if path.suffix == ".plist" else "",
        executable_path=str(target_path) if target_path is not None else "",
        program=program,
        program_arguments=args or [],
        target_exists=target_exists,
        target_hash_sha256=_hash_file(target_path) if target_exists and target_path is not None else "",
        signed_status="unknown",
        source_scanner=scanner_id,
        evidence=evidence,
        warnings=warnings,
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
        signature_cache: dict[str, object] = {}
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
                target = Path(item.executable_path) if item.executable_path else None
                if target is not None and target.is_file() and "/System/Library/" not in str(plist):
                    assessment = signature_cache.get(str(target))
                    if assessment is None:
                        assessment = SigningAssessor().assess(target)
                        signature_cache[str(target)] = assessment
                    classification = assessment.classification.value
                    item.signed_status = "apple" if classification == "apple_platform" else "valid" if classification in {"mac_app_store", "developer_id_notarized", "developer_id_valid"} else "unsigned" if classification == "unsigned" else "invalid" if classification in {"invalid", "revoked"} else "unknown"
                    item.team_id = assessment.team_identifier or ""
                    item.developer_identity = assessment.authorities[0] if assessment.authorities else ""
                    item.bundle_id = assessment.signing_identifier or ""
                    item.evidence.append(f"Target signing classification: {classification}; team={item.team_id or 'unavailable'}")
                items.append(item)
            except Exception as exc:
                errors.append(f"Failed to parse plist {plist}: {exc}")
                mechanism = "launch_daemon" if "LaunchDaemons" in str(plist) else "launch_agent"
                item = _item_from_path(mechanism, plist, label=plist.stem, scanner_id=self.scanner_id)
                item.evidence.append(f"Persistence plist exists but could not be parsed: {type(exc).__name__}")
                if not str(plist).startswith("/System/Library/"):
                    item.evidence.append("Non-system persistence is unreadable or malformed; treat unexpected removal resistance as suspicious.")
                    item.warnings.append("Preserve this plist and repeat collection through the approved privileged workflow.")
                item.confidence = "low"
                items.append(item)
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
        roots = [_system_path(context, path) for path in ("/etc/periodic", "/usr/local/etc/periodic", "/Library/Scripts", "/var/at/tabs", "/usr/lib/cron/tabs")]
        paths, warnings = _safe_iter(roots)
        for file in [context.home / ".crontab", _system_path(context, "/etc/crontab")]:
            if file.exists():
                paths.append(file)
        items = []
        for path in paths[:300]:
            item = _item_from_path("periodic" if "periodic" in str(path) else "cron", path, label=path.name, scanner_id=self.scanner_id)
            if path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")[:262144]
                    behaviors = sorted({token for token in ("curl", "wget", "bash", "python", "osascript", "base64", "http://", "https://") if token in text.lower()})
                    if behaviors:
                        item.program_arguments = behaviors
                        item.evidence.append("Scheduled job contains execution behavior requiring review: " + ", ".join(behaviors))
                except OSError as exc:
                    warnings.append(f"Unable to inspect scheduled job {path}: {exc}")
            items.append(item)
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


class SSHPersistenceScanner(PersistenceScanner):
    scanner_id = "ssh_persistence"
    name = "SSH Persistence Scanner"
    description = "Authorized keys and SSH client configuration inventory using fingerprints rather than private key contents."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        root = context.home / ".ssh"
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        for name in ("authorized_keys", "config"):
            path = root / name
            if not path.is_file():
                continue
            item = _item_from_path("ssh_authorized_key" if name == "authorized_keys" else "ssh_configuration", path, label=name, scanner_id=self.scanner_id)
            item.target_hash_sha256 = _hash_file(path)
            try:
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode & 0o077:
                    item.evidence.append(f"SSH file permissions are broader than owner-only: {oct(mode)}")
                if name == "authorized_keys":
                    fingerprints = []
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:250]:
                        clean = line.strip()
                        if not clean or clean.startswith("#"):
                            continue
                        fields = clean.split()
                        material = fields[1] if len(fields) > 1 and fields[0].startswith(("ssh-", "ecdsa-", "sk-")) else clean
                        fingerprints.append(hashlib.sha256(material.encode("utf-8")).hexdigest()[:20])
                    item.evidence.append(f"Observed {len(fingerprints)} authorized SSH key(s); bounded fingerprints: {', '.join(fingerprints[:10]) or 'none'}")
                    item.program_arguments = [f"key_fingerprint:{fingerprint}" for fingerprint in fingerprints[:10]]
            except (OSError, PermissionError) as exc:
                warnings.append(f"Unable to inspect SSH persistence file {path}: {exc}")
            items.append(item)
        return self._result(started, items, warnings)


class AppleScriptPersistenceScanner(PersistenceScanner):
    scanner_id = "applescript_persistence"
    name = "AppleScript Persistence Scanner"
    description = "Bounded AppleScript and automation inventory in user script/service locations."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        roots = [context.home / "Library/Scripts", context.home / "Library/Services", context.home / "Library/Application Scripts"]
        paths: list[Path] = []
        warnings: list[str] = []
        for root in roots:
            try:
                candidates = [*root.glob("*"), *root.glob("*/*")]
                paths.extend(path for path in candidates if path.is_file() and path.suffix.lower() in {".applescript", ".scpt", ".scptd"})
            except (OSError, PermissionError) as exc:
                warnings.append(f"Unable to inspect AppleScript location {root}: {exc}")
        items: list[PersistenceItem] = []
        for path in paths[:250]:
            item = _item_from_path("applescript_persistence", path, label=path.name, scanner_id=self.scanner_id)
            item.target_hash_sha256 = _hash_file(path)
            if path.suffix.lower() == ".applescript":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")[:262144]
                    behaviors = sorted({token for token in ("do shell script", "curl", "wget", "bash", "python", "osascript", "base64") if token in text.lower()})
                    if behaviors:
                        item.program_arguments = behaviors
                        item.evidence.append("Script contains execution behavior requiring review: " + ", ".join(behaviors))
                except OSError as exc:
                    warnings.append(f"Unable to read AppleScript source {path}: {exc}")
            items.append(item)
        return self._result(started, items, warnings)


class AuthorizationPluginScanner(PersistenceScanner):
    scanner_id = "authorization_plugins"
    name = "Authorization Plugin Scanner"

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        paths, warnings = _safe_iter([Path("/Library/Security/SecurityAgentPlugins"), Path("/System/Library/Security/SecurityAgentPlugins")])
        return self._result(started, [_item_from_path("authorization_plugin", path, label=path.name, scanner_id=self.scanner_id) for path in paths], warnings)


class LegacyAutorunScanner(PersistenceScanner):
    scanner_id = "legacy_autoruns"
    name = "Legacy and Event Autorun Scanner"
    description = "Login/logout hooks, emond rules, startup scripts, Directory Services plugins, and metadata-service bundles."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        items: list[PersistenceItem] = []
        warnings: list[str] = []

        loginwindow_plists = [
            _system_path(context, "/Library/Preferences/com.apple.loginwindow.plist"),
            context.home / "Library" / "Preferences" / "com.apple.loginwindow.plist",
        ]
        for plist in loginwindow_plists:
            if not plist.is_file():
                continue
            payload = _read_plist(plist, warnings)
            for key, mechanism in (("LoginHook", "login_hook"), ("LogoutHook", "logout_hook")):
                command = str(payload.get(key) or "").strip()
                if command:
                    items.append(_item_from_path(mechanism, plist, label=key, program=command, args=[command], scanner_id=self.scanner_id))

        startup_files = ("/etc/rc.cleanup", "/etc/rc.common", "/etc/rc.installer_cleanup", "/etc/rc.server", "/etc/launchd.conf")
        for raw_path in startup_files:
            path = _system_path(context, raw_path)
            if path.is_file():
                items.append(_item_from_path("startup_script", path, label=path.name, program=str(path), args=[str(path)], scanner_id=self.scanner_id))

        emond_config = _system_path(context, "/etc/emond.d/emond.plist")
        rule_roots = [_system_path(context, "/etc/emond.d/rules")]
        if emond_config.is_file():
            payload = _read_plist(emond_config, warnings)
            config = payload.get("config", {}) if isinstance(payload.get("config", {}), dict) else {}
            additional = config.get("additionalRulesPaths", [])
            if isinstance(additional, list):
                rule_roots.extend(_system_path(context, str(path)) for path in additional if isinstance(path, str) and path.startswith("/"))
        for rule_root in rule_roots:
            try:
                rule_files = sorted(rule_root.glob("*.plist"))[:100]
            except (OSError, PermissionError):
                warnings.append(f"Unable to inspect emond rule directory: {rule_root}")
                continue
            for rule_file in rule_files:
                try:
                    rules = plistlib.loads(rule_file.read_bytes())
                except (OSError, plistlib.InvalidFileException, ValueError, TypeError) as exc:
                    warnings.append(f"Unable to parse emond rule {rule_file}: {exc}")
                    continue
                for rule in rules if isinstance(rules, list) else []:
                    for action in rule.get("actions", []) if isinstance(rule, dict) else []:
                        command = str(action.get("command") or "").strip() if isinstance(action, dict) else ""
                        if command:
                            items.append(_item_from_path("event_rule", rule_file, label=str(rule.get("name") or rule_file.stem), program=command, args=[command], scanner_id=self.scanner_id))

        bundle_roots = (
            ("directory_services_plugin", _system_path(context, "/Library/DirectoryServices/PlugIns"), ".dsplug"),
            ("spotlight_importer", _system_path(context, "/Library/Spotlight"), ".mdimporter"),
            ("spotlight_importer", context.home / "Library" / "Spotlight", ".mdimporter"),
            ("quicklook_plugin", _system_path(context, "/Library/QuickLook"), ".qlgenerator"),
            ("quicklook_plugin", context.home / "Library" / "QuickLook", ".qlgenerator"),
        )
        for mechanism, root, suffix in bundle_roots:
            paths, path_warnings = _safe_iter([root], suffix)
            warnings.extend(path_warnings)
            items.extend(_item_from_path(mechanism, path, label=path.stem, scanner_id=self.scanner_id) for path in paths[:100])
        return self._result(started, items, warnings)


class DynamicLoaderPersistenceScanner(PersistenceScanner):
    scanner_id = "dynamic_loader_persistence"
    name = "Dynamic Loader Persistence Scanner"
    description = "Launch items and application bundles declaring inserted dynamic libraries."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        launch_roots = [
            context.home / "Library" / "LaunchAgents",
            _system_path(context, "/Library/LaunchAgents"),
            _system_path(context, "/Library/LaunchDaemons"),
        ]
        plists, path_warnings = _safe_iter(launch_roots, ".plist")
        warnings.extend(path_warnings)
        for plist in plists[:500]:
            payload = _read_plist(plist, warnings)
            environment = payload.get("EnvironmentVariables", {})
            if not isinstance(environment, dict):
                continue
            for key in ("DYLD_INSERT_LIBRARIES", "__XPC_DYLD_INSERT_LIBRARIES"):
                value = environment.get(key)
                if isinstance(value, str) and value.strip():
                    for library in value.split(":"):
                        library = library.strip()
                        if library:
                            item = _item_from_path("dylib_insert", plist, label=key, program=library, args=[library], scanner_id=self.scanner_id)
                            item.evidence.append(f"{key} declared by {plist}")
                            items.append(item)

        applications = _system_path(context, "/Applications")
        try:
            app_paths = sorted(applications.glob("*.app"))[:250]
        except (OSError, PermissionError):
            app_paths = []
            warnings.append(f"Unable to inspect applications directory: {applications}")
        for app in app_paths:
            info = app / "Contents" / "Info.plist"
            if not info.is_file():
                continue
            payload = _read_plist(info, warnings)
            environment = payload.get("LSEnvironment", {})
            if not isinstance(environment, dict):
                continue
            for key in ("DYLD_INSERT_LIBRARIES", "__XPC_DYLD_INSERT_LIBRARIES"):
                value = environment.get(key)
                if isinstance(value, str) and value.strip():
                    for library in value.split(":"):
                        library = library.strip()
                        if library:
                            item = _item_from_path("dylib_insert", info, label=f"{app.stem}:{key}", program=library, args=[library], scanner_id=self.scanner_id)
                            item.evidence.append(f"{key} declared by application {app}")
                            items.append(item)
        return self._result(started, items, warnings)


class ApplicationAutorunPluginScanner(PersistenceScanner):
    scanner_id = "application_autorun_plugins"
    name = "Application Autorun Plugin Scanner"
    description = "Embedded login helpers and Dock-hosted plugins declared by installed applications."

    def scan(self, context: ScanContext) -> ScannerResult:
        started = time.monotonic()
        items: list[PersistenceItem] = []
        warnings: list[str] = []
        roots = [_system_path(context, "/Applications"), context.home / "Applications"]
        applications: list[Path] = []
        for root in roots:
            try:
                applications.extend(sorted(root.glob("*.app"))[:250])
            except (OSError, PermissionError):
                warnings.append(f"Unable to inspect applications directory: {root}")
        for app in applications[:500]:
            info = app / "Contents" / "Info.plist"
            payload = _read_plist(info, warnings) if info.is_file() else {}
            relative = payload.get("NSDockTilePlugIn")
            if isinstance(relative, str) and relative.strip():
                plugin = app / "Contents" / "PlugIns" / relative
                items.append(_item_from_path("dock_tile_plugin", plugin, label=plugin.stem, scanner_id=self.scanner_id))
            login_items = app / "Contents" / "Library" / "LoginItems"
            try:
                helpers = sorted(login_items.glob("*.app"))[:50]
            except (OSError, PermissionError):
                helpers = []
            items.extend(_item_from_path("embedded_login_helper", helper, label=helper.stem, scanner_id=self.scanner_id) for helper in helpers)
        return self._result(started, items, warnings)


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
        SSHPersistenceScanner(),
        AppleScriptPersistenceScanner(),
        AuthorizationPluginScanner(),
        LegacyAutorunScanner(),
        DynamicLoaderPersistenceScanner(),
        ApplicationAutorunPluginScanner(),
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
    def __init__(self, context: ScanContext | None = None, scanners: list[PersistenceScanner] | None = None, trust_store: PersistenceTrustStore | None = None) -> None:
        self.context = context or ScanContext()
        self.scanners = scanners or scanner_registry()
        self.trust_store = trust_store or PersistenceTrustStore()

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
        for item in items:
            self.trust_store.apply(item)
        findings = [finding for result in results for finding in result.findings]
        warnings = [warning for result in results for warning in result.warnings]
        errors = [error for result in results for error in result.errors]
        penalty_by_mechanism = {"launch_daemon": 25, "launch_agent": 15, "ssh_authorized_key": 30, "cron": 20, "periodic": 20}
        deductions = [penalty_by_mechanism.get(item.mechanism, max(3, item.risk_score // 10)) for item in items if item.risk_level in {"MEDIUM", "HIGH", "CRITICAL"}]
        posture_score = max(0, 100 - min(100, sum(deductions)))
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

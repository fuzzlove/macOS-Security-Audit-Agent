from __future__ import annotations

import os
import plistlib
from pathlib import Path
from threading import Event
from typing import Iterable

from mac_audit_agent.performance.subprocess_runner import run_bounded_command

from .models import PersistenceRecord, ProcessRecord

DEFAULT_ROOTS = (
    Path("/Applications"), Path("/System/Applications"), Path("/System/Library/CoreServices"),
    Path("/Library"), Path.home() / "Applications", Path.home() / "Library",
    Path("/opt/homebrew/Caskroom"), Path("/usr/local/Caskroom"), Path("/Applications/MacPorts"), Path("/Volumes"),
)


def discover_applications(roots: Iterable[Path] = DEFAULT_ROOTS, *, max_depth: int = 4, limit: int = 4000, cancel: Event | None = None):
    seen: set[tuple[int, int]] = set(); yielded = 0
    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir() or root.is_symlink(): continue
        try: root_device = root.stat().st_dev
        except OSError: continue
        stack = [(root, 0)]
        while stack and yielded < limit and not (cancel and cancel.is_set()):
            current, depth = stack.pop()
            try:
                stat = current.lstat()
                identity = (stat.st_dev, stat.st_ino)
                if identity in seen or current.is_symlink() or (root != Path("/Volumes") and stat.st_dev != root_device): continue
                seen.add(identity)
                if current.suffix.lower() == ".app": yielded += 1; yield current; continue
                if depth >= max_depth: continue
                entries = list(os.scandir(current))[:2000]
            except (OSError, PermissionError): continue
            for entry in reversed(entries):
                try:
                    if entry.is_dir(follow_symlinks=False): stack.append((Path(entry.path), depth + 1))
                except OSError: continue


def bundle_metadata(bundle: Path) -> dict[str, object]:
    try: payload = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException): payload = {}
    executable = bundle / "Contents/MacOS" / str(payload.get("CFBundleExecutable", ""))
    icon_name = str(payload.get("CFBundleIconFile", ""))
    if icon_name and not Path(icon_name).suffix: icon_name += ".icns"
    icon = bundle / "Contents/Resources" / icon_name if icon_name else None
    return {
        "name": str(payload.get("CFBundleDisplayName") or payload.get("CFBundleName") or bundle.stem),
        "bundle_id": str(payload.get("CFBundleIdentifier") or "") or None,
        "version": str(payload.get("CFBundleShortVersionString") or payload.get("CFBundleVersion") or "") or None,
        "executable": executable if executable.is_file() and not executable.is_symlink() else bundle,
        "icon": icon if icon and icon.is_file() and not icon.is_symlink() else None,
    }


def discover_processes() -> tuple[ProcessRecord, ...]:
    result = run_bounded_command(["/bin/ps", "-axo", "pid=,ppid=,user=,lstart=,comm=,args="], timeout_seconds=8, max_output_bytes=2_000_000, env={"LC_ALL": "C"})
    records: list[ProcessRecord] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 9)
        if len(parts) < 10: continue
        try: pid, ppid = int(parts[0]), int(parts[1])
        except ValueError: continue
        user, started, executable, arguments = parts[2], " ".join(parts[3:8]), parts[8], parts[9]
        path = Path(executable.removesuffix(" (deleted)"))
        if not path.is_absolute(): continue
        records.append(ProcessRecord(pid, ppid, path.name, path, user, started, redact_arguments(arguments), deleted_executable=executable.endswith(" (deleted)"), privileged=user == "root"))
    return tuple(records)


def redact_arguments(value: str) -> str:
    sensitive = ("password", "passwd", "token", "secret", "authorization", "api_key", "apikey", "cookie")
    parts = value.split(); output: list[str] = []; redact_next = False
    for part in parts[:80]:
        lowered = part.lower()
        if redact_next: output.append("<redacted>"); redact_next = False; continue
        if any(key in lowered for key in sensitive):
            output.append(part.split("=", 1)[0] + "=<redacted>" if "=" in part else part)
            redact_next = "=" not in part
        else: output.append(part[:512])
    return " ".join(output)


def discover_persistence() -> tuple[PersistenceRecord, ...]:
    roots = (Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"), Path.home()/"Library/LaunchAgents")
    found: list[PersistenceRecord] = []
    for root in roots:
        if not root.is_dir(): continue
        for path in list(root.glob("*.plist"))[:2000]:
            if path.is_symlink(): continue
            try: payload = plistlib.loads(path.read_bytes())
            except (OSError, ValueError, plistlib.InvalidFileException): continue
            args = payload.get("ProgramArguments") or []
            executable = Path(str(args[0])) if args else (Path(str(payload["Program"])) if payload.get("Program") else None)
            found.append(PersistenceRecord("launchdaemon" if "LaunchDaemons" in path.parts else "launchagent", path, str(payload.get("Label") or path.stem), executable))
    return tuple(found)

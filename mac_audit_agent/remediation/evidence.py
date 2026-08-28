from __future__ import annotations

import hashlib
import json
import os
import plistlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def sha256_file(path: Path, *, limit: int = 1024 * 1024 * 1024) -> str:
    if path.is_symlink() or not path.is_file():
        return ""
    digest = hashlib.sha256(); consumed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > limit:
                return ""
            digest.update(chunk)
    return digest.hexdigest()


def collect_keylogger_evidence(finding: dict[str, Any], *, root: Path | None = None, runner=None) -> Path:
    runner = runner or _run
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    incident = Path(root or (Path.home() / "Library/Application Support/MSAA/evidence")) / (
        f"keylogger_incident_{timestamp}_{finding.get('finding_id', 'unknown')}_{uuid4().hex[:8]}"
    )
    incident.mkdir(parents=True, exist_ok=False, mode=0o700)
    path = Path(str(finding.get("path") or "")).expanduser()
    pid = int(finding.get("pid") or 0)
    stat_payload: dict[str, Any] = {}
    if path.exists() and not path.is_symlink():
        info = path.stat()
        stat_payload = {"path": str(path), "mode": oct(info.st_mode & 0o7777), "uid": info.st_uid, "gid": info.st_gid, "size": info.st_size, "mtime": info.st_mtime, "sha256": sha256_file(path)}
    commands = {
        "process_snapshot": ["/bin/ps", "-p", str(pid), "-o", "pid=,ppid=,user=,lstart=,command="] if pid else [],
        "open_files": ["/usr/sbin/lsof", "-nP", "-p", str(pid)] if pid else [],
        "network_connections": ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-iUDP"] if pid else [],
        "codesign": ["/usr/bin/codesign", "-d", "--verbose=4", str(path)] if path.exists() else [],
    }
    for name, command in commands.items():
        result = runner(command) if command else subprocess.CompletedProcess(command, 0, "", "")
        (incident / f"{name}.json").write_text(json.dumps({
            "command": command, "returncode": result.returncode,
            "stdout": (result.stdout or "")[:262144], "stderr": (result.stderr or "")[:262144],
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (incident / "binary_hashes.json").write_text(json.dumps(stat_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (incident / "finding.json").write_text(json.dumps(finding, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    persistence = discover_exact_persistence(path, str(finding.get("bundle_id") or ""))
    backup = incident / "plist_backup"; backup.mkdir(mode=0o700)
    for item in persistence:
        try:
            (backup / item.name).write_bytes(item.read_bytes())
        except OSError:
            pass
    (incident / "persistence.json").write_text(json.dumps([str(item) for item in persistence], indent=2) + "\n", encoding="utf-8")
    manifest = {item.name: sha256_file(item) for item in incident.rglob("*") if item.is_file()}
    (incident / "manifest.sha256.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return incident


def discover_exact_persistence(target: Path, bundle_id: str = "") -> list[Path]:
    roots = [
        Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    matches: list[Path] = []
    target_text = str(target.resolve(strict=False)) if str(target) else ""
    for root in roots:
        if not root.is_dir():
            continue
        for plist in root.glob("*.plist"):
            if plist.is_symlink() or plist.stat().st_size > 2 * 1024 * 1024:
                continue
            try:
                payload = plistlib.loads(plist.read_bytes())
                text = json.dumps(payload, default=str)
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if (target_text and target_text in text) or (bundle_id and bundle_id in text):
                matches.append(plist)
    return matches


def _run(command: list[str]):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


__all__ = ["collect_keylogger_evidence", "discover_exact_persistence", "sha256_file"]

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PFCTL = Path("/sbin/pfctl")
PF_CONF = Path("/etc/pf.conf")
ANCHOR_ROOT = Path("/etc/pf.anchors")
SAFE_ANCHOR = re.compile(r"^com\.liquidsky\.msaa\.firewall\.[a-z0-9][a-z0-9_-]{0,62}$")


def _run(args: list[str]) -> None:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=30)
    fatal = "\n".join(line for line in (result.stderr or "").splitlines() if "ALTQ" not in line)
    if result.returncode:
        raise RuntimeError(fatal or result.stdout or f"command failed: {' '.join(args)}")


def install_candidate(candidate: Path, anchor: str, expected_sha256: str) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("FW016: run this command with sudo; networking was not changed")
    candidate_input = candidate.expanduser()
    if candidate_input.is_symlink():
        raise ValueError("FW006: candidate path or anchor name is unsafe")
    candidate = candidate_input.resolve(strict=True)
    if not candidate.is_file() or not SAFE_ANCHOR.fullmatch(anchor):
        raise ValueError("FW006: candidate path or anchor name is unsafe")
    content = candidate.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("FW017: candidate hash changed; networking was not changed")
    _run([str(PFCTL), "-n", "-a", anchor, "-f", str(candidate)])

    destination = ANCHOR_ROOT / anchor
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pf_backup = PF_CONF.with_name(f"pf.conf.msaa-backup-{stamp}")
    anchor_backup = destination.with_name(f"{destination.name}.msaa-backup-{stamp}")
    shutil.copy2(PF_CONF, pf_backup)
    if destination.exists():
        shutil.copy2(destination, anchor_backup)
    temporary = destination.with_suffix(".pending")
    try:
        temporary.write_bytes(content)
        os.chown(temporary, 0, 0)
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        declaration = f'anchor "{anchor}"'
        loader = f'load anchor "{anchor}" from "{destination}"'
        current = PF_CONF.read_text(encoding="utf-8")
        additions = [line for line in (declaration, loader) if line not in current.splitlines()]
        if additions:
            PF_CONF.write_text(current.rstrip() + "\n\n# MSAA managed anchor\n" + "\n".join(additions) + "\n", encoding="utf-8")
        _run([str(PFCTL), "-n", "-f", str(PF_CONF)])
        if additions:
            _run([str(PFCTL), "-f", str(PF_CONF)])
        else:
            _run([str(PFCTL), "-a", anchor, "-f", str(destination)])
    except Exception:
        shutil.copy2(pf_backup, PF_CONF)
        if anchor_backup.exists():
            shutil.copy2(anchor_backup, destination)
        elif destination.exists():
            destination.unlink()
        try:
            _run([str(PFCTL), "-f", str(PF_CONF)])
        except Exception:
            pass
        raise
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install one validated MSAA PF anchor with explicit sudo authorization.")
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    installed = install_candidate(args.candidate, args.anchor, args.sha256)
    print(f"Installed and loaded {args.anchor} from {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

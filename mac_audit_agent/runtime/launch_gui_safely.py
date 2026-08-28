"""Select an app bundle or validated Python without entering an unsafe GUI path."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


APP_BUNDLE_CANDIDATES = (Path("dist/MSAA.app"), Path("dist/macOS Security Audit Agent.app"))
PYTHON_CANDIDATES = ("python3.13", "python3.12", "python3.11", "python3.10")


def _probe_python(executable: str) -> dict[str, Any]:
    code = "from mac_audit_agent.runtime.macos_gui_preflight import run_macos_gui_preflight; import json; print(json.dumps(run_macos_gui_preflight().to_dict()))"
    try:
        result = subprocess.run([executable, "-c", code], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"allowed": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    try:
        payload = json.loads((result.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        payload = {"allowed": False, "error": (result.stderr or result.stdout)[-1000:]}
    payload["returncode"] = result.returncode
    return payload


def select_safe_gui_target(root: Path | None = None) -> dict[str, Any]:
    project_root = Path(root or Path.cwd()).resolve()
    for relative in APP_BUNDLE_CANDIDATES:
        candidate = project_root / relative
        if candidate.is_dir():
            return {"kind": "app_bundle", "path": str(candidate), "command": ["open", str(candidate)]}
    probes: list[dict[str, Any]] = []
    for name in PYTHON_CANDIDATES:
        executable = shutil.which(name)
        if not executable:
            continue
        probe = _probe_python(executable)
        probes.append({"executable": executable, "preflight": probe})
        if probe.get("allowed"):
            return {"kind": "python", "path": executable, "command": [executable, str(project_root / "launcher.py"), "--gui"], "probes": probes}
    return {"kind": "blocked", "command": [sys.executable, "-m", "mac_audit_agent", "--doctor"], "probes": probes}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Select a crash-safe MSAA GUI launch target.")
    parser.add_argument("--open", action="store_true", help="Open/re-exec the selected safe target.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = select_safe_gui_target()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("MSAA safe GUI selection: %s" % result["kind"])
        print("Recommended command: %s" % " ".join(str(item) for item in result["command"]))
    if args.open and result["kind"] != "blocked":
        return subprocess.run(result["command"], check=False).returncode
    return 0 if result["kind"] != "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["select_safe_gui_target", "main"]

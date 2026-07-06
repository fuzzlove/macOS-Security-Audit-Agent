from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.quality.verification_evidence import record_verification_evidence
from mac_audit_agent.storage import AuditDatabase


COMMANDS = {
    "compileall": {
        "gate_key": "compileall_passes",
        "check": "compileall passes",
        "argv": ["-m", "compileall", "-q", "mac_audit_agent"],
    },
    "pytest": {
        "gate_key": "tests_pass",
        "check": "tests pass",
        "argv": ["-m", "pytest", "-v"],
    },
    "build": {
        "gate_key": "python_m_build_passes",
        "check": "python -m build passes",
        "argv": ["-m", "build"],
    },
}

SUPPORTED_PYTHON_MIN = (3, 10)
SUPPORTED_PYTHON_MAX_TESTED = (3, 13)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run and record MSAA release verification evidence.")
    parser.add_argument("--all", action="store_true", help="Run compileall, pytest, build, twine check, and feasible clean install evidence checks.")
    parser.add_argument("--compileall", action="store_true", help="Run compileall evidence check.")
    parser.add_argument("--pytest", action="store_true", help="Run pytest evidence check.")
    parser.add_argument("--build", action="store_true", help="Run python -m build evidence check.")
    parser.add_argument("--twine", action="store_true", help="Run twine check dist/* evidence check.")
    parser.add_argument("--clean-install", action="store_true", help="Record clean wheel install verification placeholder if no dedicated report exists.")
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="Python interpreter to use for release verification commands.")
    parser.add_argument("--db", type=Path, default=Path.home() / ".mac_audit_agent.sqlite3", help="Database path for release readiness gate evidence.")
    parser.add_argument("--output-dir", type=Path, default=Path("release_evidence"), help="Directory for command output logs.")
    return parser


def _run_command(name: str, argv: list[str], *, output_dir: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    started = utc_now_iso()
    start = time.monotonic()
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{name.replace(' ', '_')}.log"
    try:
        result = subprocess.run(argv, cwd=Path.cwd(), capture_output=True, text=True, check=False, timeout=900, env=env)
        exit_code = result.returncode
        output = (result.stdout or "") + ("\n" if result.stdout and result.stderr else "") + (result.stderr or "")
    except Exception as exc:
        exit_code = 1
        output = f"{type(exc).__name__}: {exc}"
    out_path.write_text(output[-20000:], encoding="utf-8")
    completed = utc_now_iso()
    return {
        "name": name,
        "command": " ".join(argv),
        "started_at": started,
        "completed_at": completed,
        "exit_code": exit_code,
        "duration_seconds": round(time.monotonic() - start, 2),
        "output_path": str(out_path),
        "status": "pass" if exit_code == 0 else "fail",
        "output_tail": output[-1200:],
    }


def _python_info(python: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(python), "-c", "import json,sys; print(json.dumps({'executable': sys.executable, 'version': sys.version, 'major': sys.version_info[0], 'minor': sys.version_info[1], 'micro': sys.version_info[2]}))"],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    try:
        payload = json.loads(result.stdout.strip()) if result.returncode == 0 else {}
    except json.JSONDecodeError:
        payload = {}
    version = (int(payload.get("major", 0) or 0), int(payload.get("minor", 0) or 0))
    payload["supported_for_release"] = SUPPORTED_PYTHON_MIN <= version <= SUPPORTED_PYTHON_MAX_TESTED
    payload["supported_range"] = "Python 3.10 through 3.13"
    payload["warning"] = "" if payload["supported_for_release"] else "Release verification should use Python 3.10, 3.11, 3.12, or 3.13 unless explicitly validating newer interpreter compatibility."
    payload["probe_returncode"] = result.returncode
    payload["probe_stderr"] = result.stderr[-1000:]
    return payload


def _record_gate(db: AuditDatabase, *, gate_key: str, check: str, result: dict[str, Any]) -> None:
    payload = {
        "generated_at": result["completed_at"],
        "check": {
            "check": check,
            "status": "pass" if result["exit_code"] == 0 else "block",
            "evidence": json.dumps(
                {
                    "command": result["command"],
                    "exit_code": result["exit_code"],
                    "output_path": result["output_path"],
                    "duration_seconds": result["duration_seconds"],
                    "python": result.get("python", {}),
                },
                sort_keys=True,
            ),
            "recommended_fix": "Review command output and fix release verification failures.",
        },
    }
    db.set_background_monitor_state(f"release_readiness_gate:{gate_key}", json.dumps(payload, sort_keys=True))


def _record_quality_evidence(*, output_dir: Path, **kwargs) -> None:
    try:
        record_verification_evidence(**kwargs)
    except OSError:
        record_verification_evidence(**kwargs, path=output_dir / "verification_evidence.json")


def _twine_argv(python: Path) -> list[str]:
    artifacts = sorted(str(path) for path in Path("dist").glob("*") if path.is_file())
    return [str(python), "-m", "twine", "check", *artifacts] if artifacts else [str(python), "-m", "twine", "check", "dist/*"]


def run_release_verify(args: argparse.Namespace) -> list[dict[str, Any]]:
    selected = {
        "compileall": args.all or args.compileall,
        "pytest": args.all or args.pytest,
        "build": args.all or args.build,
        "twine": args.all or args.twine,
        "clean_install": args.all or args.clean_install,
    }
    db = AuditDatabase(args.db.expanduser())
    output_dir = args.output_dir.expanduser()
    python = args.python.expanduser()
    python_info = _python_info(python)
    results: list[dict[str, Any]] = []
    for name, spec in COMMANDS.items():
        if not selected[name]:
            continue
        env = None
        if name == "compileall":
            env = os.environ.copy()
            cache_dir = tempfile.mkdtemp(prefix="msaa-release-compileall-")
            env["PYTHONPYCACHEPREFIX"] = cache_dir
        result = _run_command(name, [str(python), *spec["argv"]], output_dir=output_dir, env=env)
        result["python"] = python_info
        results.append(result)
        _record_gate(db, gate_key=str(spec["gate_key"]), check=str(spec["check"]), result=result)
        _record_quality_evidence(
            output_dir=output_dir,
            check_id=f"release.{name}",
            command=result["command"],
            started_at=result["started_at"],
            completed_at=result["completed_at"],
            status=result["status"],
            exit_code=result["exit_code"],
            evidence_summary=f"{name} release verification {'passed' if result['exit_code'] == 0 else 'failed'}.",
            artifacts=[result["output_path"]],
            details=result,
        )
    if selected["twine"]:
        result = _run_command("twine", _twine_argv(python), output_dir=output_dir)
        result["python"] = python_info
        results.append(result)
        _record_gate(db, gate_key="twine_check_passes", check="twine check passes", result=result)
        _record_quality_evidence(
            output_dir=output_dir,
            check_id="release.twine",
            command=result["command"],
            started_at=result["started_at"],
            completed_at=result["completed_at"],
            status=result["status"],
            exit_code=result["exit_code"],
            evidence_summary=f"twine release verification {'passed' if result['exit_code'] == 0 else 'failed'}.",
            artifacts=[result["output_path"]],
            details=result,
        )
    if selected["clean_install"]:
        wheel = sorted(Path("dist").glob("*.whl"), key=lambda path: path.stat().st_mtime, reverse=True)
        clean_argv = [
            str(python),
            "-m",
            "mac_audit_agent.cli",
            "--db",
            str(args.db.expanduser()),
            "--verify-clean-install",
            "--clean-install-python",
            str(python),
        ]
        if wheel:
            clean_argv.extend(["--clean-install-wheel", str(wheel[0])])
        result = _run_command("clean_install", clean_argv, output_dir=output_dir)
        result["python"] = python_info
        results.append(result)
        raw = db.get_background_monitor_state("clean_install_last_report_json", "")
        status = "pass" if result["exit_code"] == 0 and raw else "fail"
        _record_quality_evidence(
            output_dir=output_dir,
            check_id="release.clean_wheel_install",
            command=result["command"],
            started_at=result["started_at"],
            completed_at=result["completed_at"],
            status=status,
            exit_code=result["exit_code"],
            evidence_summary="Clean wheel install verification passed." if status == "pass" else "Clean wheel install verification failed.",
            artifacts=[result["output_path"]],
            details={**result, "clean_install_last_report_json_present": bool(raw)},
        )
    return results


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not any([args.all, args.compileall, args.pytest, args.build, args.twine, args.clean_install]):
        args.all = True
    results = run_release_verify(args)
    print(json.dumps({"results": results}, indent=2, sort_keys=True))
    return 0 if all(int(item.get("exit_code", 1)) == 0 for item in results if item.get("name") != "clean_install") else 1


if __name__ == "__main__":
    raise SystemExit(main())

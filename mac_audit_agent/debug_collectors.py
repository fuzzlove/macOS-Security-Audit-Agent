from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.analyzers import parse_lsof_listening_output, parse_ps_axo_output
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import AuditCommand, get_exit_code, get_stderr, get_stdout
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner


@dataclass
class DebugSection:
    name: str
    command: str
    stdout_preview: list[str]
    parsed_count: int
    parsed_rows: list[dict[str, Any]]
    exit_code: int | None
    stderr: str


def _make_command(command_id: str, name: str, argv: list[str], category: str) -> AuditCommand:
    return AuditCommand(
        id=command_id,
        name=name,
        description=name,
        command=argv,
        privilege_required=False,
        risk_level="safe",
        mutates_system=False,
        timeout_seconds=10,
        collection_warning="Read-only local diagnostics.",
        failure_modes=["Command unavailable.", "Permission denied.", "Output parsing failed."],
        user_disclaimer="Local read-only inspection only.",
        safer_alternative="Run the command manually in Terminal.",
        category=category,
    )


def _preview_lines(text: str, limit: int = 10) -> list[str]:
    return text.splitlines()[:limit]


def _run_command(runner: SafeCommandRunner, command: AuditCommand) -> tuple[str, str, int | None]:
    result = runner.execute(command)
    return get_stdout(result), get_stderr(result), get_exit_code(result)


def collect_debug_snapshot(*, runner: SafeCommandRunner | None = None, config: AuditConfig | None = None) -> dict[str, Any]:
    config = config or AuditConfig()
    runner = runner or SafeCommandRunner(RunnerConfig(dry_run=False))
    stdout, stderr, exit_code = _run_command(
        runner,
        _make_command(
            "debug.ports.lsof_tcp",
            "Listening TCP Ports",
            ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            "Network",
        ),
    )
    ports_rows = parse_lsof_listening_output(stdout, config)
    process_stdout, process_stderr, process_exit_code = _run_command(
        runner,
        _make_command(
            "debug.processes.ps_axo",
            "Process List",
            ["/bin/ps", "-axo", "user=,pid=,ppid=,comm=,args="],
            "Files & Processes",
        ),
    )
    process_rows = parse_ps_axo_output(process_stdout)
    artifacts = {
        "ports": {
            "listening": ports_rows,
            "active_connections": [],
            "suspicious_review_needed": [row for row in ports_rows if row.get("concern")],
            "errors": [stderr] if stderr else [],
        },
        "processes": {
            "all": process_rows,
            "suspicious": [row for row in process_rows if row.get("suspicious_reasons")],
            "errors": [process_stderr] if process_stderr else [],
        },
    }
    return {
        "ports": DebugSection(
            name="ports",
            command="/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN",
            stdout_preview=_preview_lines(stdout),
            parsed_count=len(ports_rows),
            parsed_rows=ports_rows[:5],
            exit_code=exit_code,
            stderr=stderr,
        ),
        "processes": DebugSection(
            name="processes",
            command="/bin/ps -axo user=,pid=,ppid=,comm=,args=",
            stdout_preview=_preview_lines(process_stdout),
            parsed_count=len(process_rows),
            parsed_rows=process_rows[:5],
            exit_code=process_exit_code,
            stderr=process_stderr,
        ),
        "artifacts": artifacts,
    }


def _print_section(title: str, section: DebugSection) -> None:
    print(title)
    print(f"command: {section.command}")
    print("raw stdout first 10 lines:")
    for line in section.stdout_preview:
        print(line)
    print(f"exit_code: {section.exit_code}")
    print(f"stderr: {section.stderr}")
    print(f"parsed count: {section.parsed_count}")
    print("parsed first 5 rows:")
    print(json.dumps(section.parsed_rows, indent=2, sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Debug ports and processes collectors.")
    parser.add_argument("--dry-run", action="store_true", help="Preview commands without executing them.")
    args = parser.parse_args(argv)

    runner = SafeCommandRunner(RunnerConfig(dry_run=args.dry_run))
    snapshot = collect_debug_snapshot(runner=runner)

    _print_section("Ports", snapshot["ports"])
    _print_section("Processes", snapshot["processes"])
    print("final artifact keys:")
    print(json.dumps(list(snapshot["artifacts"].keys()), indent=2))
    print("nested artifact keys:")
    print(json.dumps({key: list(value.keys()) for key, value in snapshot["artifacts"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

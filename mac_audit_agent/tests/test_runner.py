from mac_audit_agent.models import AuditCommand
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner


def make_command(command: list[str], timeout_seconds: int = 1) -> AuditCommand:
    return AuditCommand(
        id="test.command",
        name="Test Command",
        description="Test command.",
        command=command,
        privilege_required=False,
        risk_level="safe",
        mutates_system=False,
        timeout_seconds=timeout_seconds,
        collection_warning="",
        failure_modes=[""],
        user_disclaimer="Test only.",
        safer_alternative="None",
        category="Test",
    )


def test_runner_blocks_dangerous_without_approval() -> None:
    runner = SafeCommandRunner(RunnerConfig(dry_run=False))
    command = make_command(["/bin/echo", "hello"])
    command = AuditCommand(**{**command.to_dict(), "risk_level": "dangerous"})
    result = runner.execute(command)
    assert result.exit_code == 126
    assert "blocked" in result.stderr.lower()


def test_runner_dry_run_skips_execution() -> None:
    runner = SafeCommandRunner(RunnerConfig(dry_run=True))
    result = runner.execute(make_command(["/bin/echo", "hello"]))
    assert result.dry_run is True
    assert result.exit_code is None
    assert result.stdout == ""
    assert result.stderr == ""


def test_runner_truncates_large_output() -> None:
    runner = SafeCommandRunner(RunnerConfig(dry_run=False, max_output_bytes=16))
    result = runner.execute(make_command(["/bin/echo", "abcdefghijklmnopqrstuvwxyz"]))
    assert result.truncated is True


def test_runner_handles_missing_command() -> None:
    runner = SafeCommandRunner(RunnerConfig(dry_run=False))
    result = runner.execute(make_command(["/definitely/missing/binary"]))
    assert result.exit_code == 1
    assert result.stderr

from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.quality.force_auditor import run_force_audit
from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.quality.audit_models import AuditContext
from mac_audit_agent.runtime.force_mode import (
    ForceArgumentError,
    ForceMode,
    force_diagnostics,
    log_force_action,
    parse_force_argument,
    strip_force_tokens,
)


def test_force_parser_accepts_supported_forms() -> None:
    for argv in (["scan", "--force"], ["scan", "-f"], ["scan", "force"], ["scan", "force=true"]):
        cleaned, mode = parse_force_argument(argv, command="scan", supported_scopes={"rescan"}, default_scope="rescan")
        assert mode.enabled is True
        assert "force" not in cleaned
        assert mode.destructive_allowed is False
        assert mode.bypass_integrity_allowed is False
        assert mode.bypass_safety_allowed is False


def test_force_false_disables_force_and_duplicate_force_is_safe() -> None:
    cleaned, value, _source = strip_force_tokens(["scan", "--force", "force=true", "force=false"])
    assert cleaned == ["scan"]
    assert value is False
    _cleaned, mode = parse_force_argument(["scan", "force=false"], command="scan", supported_scopes={"rescan"}, default_scope="rescan")
    assert mode.enabled is False


def test_force_alone_requires_action() -> None:
    try:
        parse_force_argument(["force"], command="", supported_scopes={"rescan"})
    except ForceArgumentError as exc:
        assert "Specify what to force" in str(exc)
    else:
        raise AssertionError("force alone should fail")


def test_unsupported_and_unsafe_force_are_rejected() -> None:
    try:
        parse_force_argument(["unknown", "force"], command="unknown", supported_scopes={"rescan"}, default_scope="unsupported")
    except ForceArgumentError as exc:
        assert "Force is not supported" in str(exc)
    else:
        raise AssertionError("unsupported force should fail")
    for command, scope in [
        ("integrity trust --force", "trust"),
        ("delete evidence --force", "delete_evidence"),
        ("suppress alerts --force", "suppress_alerts"),
        ("external scan --force", "external_scan"),
    ]:
        try:
            parse_force_argument(command.split(), command=command, supported_scopes={"rescan"}, default_scope=scope)
        except ForceArgumentError as exc:
            assert "refused" in str(exc) or "not supported" in str(exc)
        else:
            raise AssertionError(f"{command} should fail")


def test_force_logging_and_diagnostics(tmp_path: Path) -> None:
    log_path = tmp_path / "actions.log"
    log_force_action("scan --force", ForceMode(enabled=True, scope="rescan"), action_taken="test", result="accepted", log_path=log_path)
    log_force_action("delete evidence --force", ForceMode(enabled=False, scope="delete_evidence"), result="rejected", error="Force was refused because this action could alter security state or evidence.", log_path=log_path)
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["force_enabled"] is True
    diagnostics = force_diagnostics(log_path)
    assert diagnostics["last_force_rejection_reason"]


def test_force_pre_uat_checks_registered_and_pass(tmp_path: Path) -> None:
    check_ids = {check.check_id for check in build_registry()}
    assert "cli.force_keyword_supported" in check_ids
    assert "cli.force_unsafe_rejected" in check_ids
    context = AuditContext(db_path=tmp_path / "audit.sqlite", output_dir=tmp_path, mode="settings")
    checks = run_force_audit(context)
    assert checks
    assert all(check.status == "PASS" for check in checks)

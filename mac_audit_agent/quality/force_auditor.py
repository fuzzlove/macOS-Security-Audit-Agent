from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.runtime.force_mode import ForceArgumentError, ForceMode, force_diagnostics, log_force_action, parse_force_argument


def run_force_audit(context: AuditContext) -> list[FunctionalCheck]:
    checks: list[FunctionalCheck] = []
    parser_check = FunctionalCheck("cli.force_keyword_supported", "CLI", "force keyword supported", "Parser accepts --force, -f, force, force=true, and force=false.", "high", "unit")
    unsupported_check = FunctionalCheck("cli.force_unsupported_helpful_error", "CLI", "unsupported force error", "Unsupported force usage gives clear help.", "medium", "unit")
    safe_check = FunctionalCheck("cli.force_safe_commands", "CLI", "safe force commands", "Force works for approved safe actions.", "high", "unit")
    unsafe_check = FunctionalCheck("cli.force_unsafe_rejected", "CLI", "unsafe force rejected", "Unsafe force actions are blocked.", "blocker", "unit")
    integrity_check = FunctionalCheck("integrity.force_no_silent_trust", "Integrity", "force no silent trust", "Integrity verify --force does not rebaseline or trust new hashes.", "blocker", "unit")
    alerts_check = FunctionalCheck("alerts.force_no_suppression", "Alerts", "force no suppression", "Force does not suppress alerts.", "blocker", "unit")
    logs_check = FunctionalCheck("logs.force_audit_trail", "Logs", "force audit trail", "Force actions and rejections are logged.", "high", "unit")

    try:
        cases = [
            (["scan", "--force"], True),
            (["scan", "-f"], True),
            (["scan", "force"], True),
            (["scan", "force=true"], True),
            (["scan", "force=false"], False),
            (["scan", "--force", "force=true"], True),
        ]
        parsed = []
        for argv, expected in cases:
            cleaned, mode = parse_force_argument(argv, command="scan", supported_scopes={"rescan"}, default_scope="rescan")
            parsed.append({"argv": argv, "cleaned": cleaned, "enabled": mode.enabled})
            if mode.enabled is not expected:
                raise AssertionError(f"{argv} expected force={expected} got {mode.enabled}")
        checks.append(parser_check.passed("Force parser accepts supported forms.", {"cases": parsed}))
    except Exception as exc:
        checks.append(parser_check.failed(str(exc), "Fix parse_force_argument to normalize all force forms without crashing.", {"exception": type(exc).__name__}))

    try:
        try:
            parse_force_argument(["thing", "force"], command="unknown", supported_scopes={"rescan"}, default_scope="unsupported")
            raise AssertionError("unsupported force was accepted")
        except ForceArgumentError as exc:
            message = str(exc)
            assert "Force is not supported" in message
        checks.append(unsupported_check.passed("Unsupported force usage returns helpful text.", {"message": message}))
    except Exception as exc:
        checks.append(unsupported_check.failed(str(exc), "Return helpful unsupported-force errors.", {"exception": type(exc).__name__}))

    try:
        safe_cases = {
            "scan --force": ("rescan", {"rescan"}),
            "refresh --force": ("refresh", {"refresh"}),
            "repair-notifier --force": ("repair", {"repair"}),
            "release verify --force": ("diagnostics", {"diagnostics"}),
        }
        evidence = {}
        for command, (scope, allowed) in safe_cases.items():
            _, mode = parse_force_argument(command.split(), command=command, supported_scopes=allowed, default_scope=scope)
            evidence[command] = mode.to_dict()
            assert mode.enabled and mode.scope == scope
            assert not mode.destructive_allowed and not mode.bypass_safety_allowed and not mode.bypass_integrity_allowed
        checks.append(safe_check.passed("Safe force scopes are accepted without bypass flags.", evidence))
    except Exception as exc:
        checks.append(safe_check.failed(str(exc), "Keep force limited to cache bypass/retry semantics.", {"exception": type(exc).__name__}))

    try:
        rejected = []
        for command, scope in [
            ("integrity trust --force", "trust"),
            ("delete evidence --force", "delete_evidence"),
            ("suppress alerts --force", "suppress_alerts"),
            ("external scan --force", "external_scan"),
        ]:
            try:
                parse_force_argument(command.split(), command=command, supported_scopes={"rescan"}, default_scope=scope)
                raise AssertionError(f"{command} accepted")
            except ForceArgumentError as exc:
                rejected.append({"command": command, "message": str(exc)})
        checks.append(unsafe_check.passed("Unsafe force scopes are rejected.", {"rejected": rejected}))
    except Exception as exc:
        checks.append(unsafe_check.failed(str(exc), "Reject force for trust, delete, suppression, security-control, and external-scan actions.", {"exception": type(exc).__name__}))

    try:
        _, mode = parse_force_argument(["verify", "--force"], command="integrity verify", supported_scopes={"diagnostics"}, default_scope="diagnostics")
        assert mode.enabled and not mode.bypass_integrity_allowed
        checks.append(integrity_check.passed("Integrity force verification reruns only and cannot rebaseline.", mode.to_dict()))
    except Exception as exc:
        checks.append(integrity_check.failed(str(exc), "Force must never rebaseline or silently trust hashes.", {"exception": type(exc).__name__}))

    try:
        _, mode = parse_force_argument(["alert", "--force"], command="alert diagnostics", supported_scopes={"diagnostics"}, default_scope="diagnostics")
        assert mode.enabled
        assert "Force does not delete evidence or suppress alerts." in mode.warnings
        checks.append(alerts_check.passed("Force warnings explicitly preserve alert behavior.", mode.to_dict()))
    except Exception as exc:
        checks.append(alerts_check.failed(str(exc), "Force must not suppress high/critical alerts.", {"exception": type(exc).__name__}))

    try:
        log_path = context.output_dir / "force_actions.log"
        accepted = ForceMode(enabled=True, source="cli_flag", scope="rescan", reason="pre-uat accepted force")
        rejected = ForceMode(enabled=False, source="cli_keyword", scope="unsupported", reason="pre-uat rejected force")
        log_force_action("scan --force", accepted, action_taken="pre_uat_probe", result="accepted", log_path=log_path)
        log_force_action("delete evidence --force", rejected, result="rejected", error="Force was refused because this action could alter security state or evidence.", log_path=log_path)
        diagnostics = force_diagnostics(log_path)
        assert log_path.exists()
        assert diagnostics["last_force_rejection_reason"]
        checks.append(logs_check.passed("Force action audit trail recorded accepted and rejected force actions.", {"log_path": str(log_path), "diagnostics": diagnostics}))
    except Exception as exc:
        checks.append(logs_check.failed(str(exc), "Write force action/rejection records to the audit trail.", {"exception": type(exc).__name__}))

    return checks


__all__ = ["run_force_audit"]

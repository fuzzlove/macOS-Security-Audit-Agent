from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.auto_sign import AutoSignError, AutoSignResult, auto_sign_integrity


REQUIRED_SOURCE_BASELINE_CONFIRMATION = "APPROVE SOURCE BASELINE"


def repair_and_sign_integrity(
    root: Path,
    *,
    policy: str = "dev",
    author: str,
    reason: str,
    build_id: str = "",
    developer_machine: bool = False,
    verify_pre_uat_compatible: bool = True,
    migrate_legacy: bool = True,
    exclude_generated: bool = True,
    approve_current_source: bool = False,
    typed_confirmation: str = "",
    dry_run: bool = False,
    audit_log: Path | None = None,
) -> AutoSignResult:
    if approve_current_source and typed_confirmation and typed_confirmation != REQUIRED_SOURCE_BASELINE_CONFIRMATION:
        raise AutoSignError("typed confirmation must exactly match APPROVE SOURCE BASELINE")
    return auto_sign_integrity(
        root,
        policy=policy,
        author=author,
        reason=reason,
        build_id=build_id,
        developer_machine=developer_machine,
        verify_pre_uat_compatible=verify_pre_uat_compatible,
        migrate_legacy=migrate_legacy,
        exclude_generated=exclude_generated,
        approve_current_source=approve_current_source,
        typed_confirmation=typed_confirmation,
        dry_run=dry_run,
        audit_log=audit_log,
        evidence_prefix="integrity_repair_and_sign",
        command_label="python -m mac_audit_agent.integrity repair-and-sign",
    )


__all__ = ["REQUIRED_SOURCE_BASELINE_CONFIRMATION", "repair_and_sign_integrity"]

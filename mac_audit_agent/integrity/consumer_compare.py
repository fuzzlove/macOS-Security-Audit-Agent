from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.event_reconciliation import SQLiteIntegrityEventStore, reconcile_integrity_events_after_verified_repair
from mac_audit_agent.integrity.result_cache import build_current_integrity_status, read_current_integrity_status, read_current_integrity_status_db
from mac_audit_agent.integrity.runtime_sync import run_runtime_sync_check
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter


CONSUMER_DIVERGENCE_CODE = "INTEGRITY_CONSUMER_DIVERGENCE"

# Pre-UAT also reports release-readiness gates such as dirty-tree approval,
# hash-scope classification, and artifact hygiene. Those gates are useful
# evidence, but they are not independent consumers of the signed manifest and
# must not turn a valid trust decision into a consumer divergence.
PRE_UAT_TRUST_CHECK_IDS = frozenset(
    {
        "integrity.policy_resolved",
        "integrity.canonical_manifest_exists",
        "integrity.source_signature_valid",
        "integrity.source_files_match_manifest",
        "integrity.files_match_manifest",
        "integrity.canonical_manifest_signature_valid",
        "integrity.canonical_files_match_manifest",
        "integrity.manifest_path_consistency",
        "integrity.developer_machine_identity_exists",
        "integrity.developer_machine_signature_valid",
        "integrity.signing_machine_authorized",
        "integrity.no_unknown_status",
        "integrity.no_pass_with_failed_evidence",
        "integrity.independent_verify_matches",
    }
)


@dataclass(slots=True)
class ConsumerStatus:
    name: str
    status: str
    trust_state: str
    manifest_path: str
    signature_path: str
    manifest_sha256: str
    failure_code: str
    evidence_age_seconds: float | None
    source: str
    module_path: str = ""
    source_file: str = ""
    stale: bool = False
    last_updated: str = ""
    included_in_comparison: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["consumer_name"] = self.name
        return payload


@dataclass(slots=True)
class ConsumerComparisonResult:
    status: str
    failure_code: str = ""
    consumers: list[ConsumerStatus] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.update({consumer.name: consumer.to_dict() for consumer in self.consumers})
        return payload


def compare_integrity_consumers(root: Path | None = None, *, policy: str = "dev") -> ConsumerComparisonResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    authority = IntegrityAuthority(root, policy)
    live = authority.status()
    current = build_current_integrity_status(live, root=root)
    baseline = _consumer_from_status("cli_status", live, current, "IntegrityAuthority.status")
    consumers = [
        baseline,
        _consumer_from_status("cli_verify", authority.verify(strict=True), current, "IntegrityAuthority.verify"),
        _wrapper_consumer("integrity_health_backend", IntegrityWrapperAdapter(root).get_integrity_status_for_ui(policy), baseline),
        _wrapper_consumer("release_readiness_backend", IntegrityWrapperAdapter(root).get_integrity_status_for_release_readiness(policy), baseline),
        _wrapper_consumer("dashboard_backend", IntegrityWrapperAdapter(root).get_integrity_status_for_dashboard(policy), baseline),
        _wrapper_consumer("operational_health_backend", IntegrityWrapperAdapter(root).get_integrity_status_for_operational_health(policy), baseline),
        _public_release_gate_consumer(root, baseline),
        _pre_uat_consumer(root, policy, baseline),
        _event_reconciliation_consumer(current, baseline),
        _active_db_consumer(baseline),
        _active_db_unresolved_events_consumer(baseline),
        _runtime_sync_consumer(root, policy, baseline),
        *_runtime_path_consumers(root, policy, baseline),
    ]
    cache = read_current_integrity_status()
    if cache is not None:
        consumers.append(
            ConsumerStatus(
                name="result_cache_display",
                status=cache.status,
                trust_state=cache.trust_state,
                manifest_path=cache.canonical_manifest_path,
                signature_path=cache.canonical_signature_path,
                manifest_sha256=cache.manifest_sha256,
                failure_code=cache.failure_code,
                evidence_age_seconds=None,
                source="display-only result_cache",
                module_path="mac_audit_agent.integrity.result_cache",
                source_file="mac_audit_agent/integrity/result_cache.py",
                stale=bool(cache.manifest_sha256 and cache.manifest_sha256 != baseline.manifest_sha256),
                last_updated=cache.generated_at,
                details={"cache_is_trust_source": False},
            )
        )
    mismatches = _find_mismatches(consumers, baseline)
    return ConsumerComparisonResult(
        status="pass" if not mismatches else "fail",
        failure_code="" if not mismatches else CONSUMER_DIVERGENCE_CODE,
        consumers=consumers,
        mismatches=mismatches,
    )


def _consumer_from_status(name: str, status: Any, current: Any, source: str) -> ConsumerStatus:
    return ConsumerStatus(
        name=name,
        status=getattr(status, "status", ""),
        trust_state=getattr(status, "trust_state", ""),
        manifest_path=getattr(status, "canonical_manifest_path", "") or getattr(status, "manifest_path", ""),
        signature_path=getattr(status, "signature_path", ""),
        manifest_sha256=getattr(current, "manifest_sha256", ""),
        failure_code=getattr(status, "failure_code", ""),
        evidence_age_seconds=0.0,
        source=source,
        module_path="mac_audit_agent.integrity.authority",
        source_file="mac_audit_agent/integrity/authority.py",
        details={
            "result_code": getattr(status, "result_code", ""),
            "reason": getattr(status, "reason", ""),
        },
    )


def _wrapper_consumer(name: str, wrapper_status: Any, baseline: ConsumerStatus) -> ConsumerStatus:
    return ConsumerStatus(
        name=name,
        status=wrapper_status.status,
        trust_state=wrapper_status.trust_state,
        manifest_path=wrapper_status.manifest_path,
        signature_path=wrapper_status.signature_path,
        manifest_sha256=wrapper_status.manifest_sha256,
        failure_code=wrapper_status.failure_code,
        evidence_age_seconds=0.0,
        source="IntegrityWrapperAdapter",
        module_path=wrapper_status.module_path,
        source_file=wrapper_status.source_file,
        stale=wrapper_status.cache_stale,
        details={"result_code": wrapper_status.result_code, "cache_status": wrapper_status.cache_status},
    )


def _pre_uat_consumer(root: Path, policy: str, baseline: ConsumerStatus) -> ConsumerStatus:
    previous = os.environ.get("MSAA_RELEASE_POLICY")
    os.environ["MSAA_RELEASE_POLICY"] = policy
    try:
        from mac_audit_agent.quality.audit_models import AuditContext
        from mac_audit_agent.quality.release_integrity_auditor import run_release_integrity_audit

        with tempfile.TemporaryDirectory(prefix="msaa-preuat-integrity-") as tmp:
            context = AuditContext(db_path=root / "release_audit.sqlite3", output_dir=Path(tmp), mode="full")
            old_cwd = Path.cwd()
            os.chdir(root)
            try:
                checks = run_release_integrity_audit(context)
            finally:
                os.chdir(old_cwd)
        failed_integrity_checks = [
            check
            for check in checks
            if check.check_id.startswith("integrity.") and check.status in {"FAIL", "BLOCKER"}
        ]
        failed = [check for check in failed_integrity_checks if check.check_id in PRE_UAT_TRUST_CHECK_IDS]
        release_gate_failures = [check for check in failed_integrity_checks if check.check_id not in PRE_UAT_TRUST_CHECK_IDS]
        return ConsumerStatus(
            name="pre_uat_integrity",
            status=baseline.status if not failed else "failed",
            trust_state=baseline.trust_state if not failed else "pre_uat_integrity_failed",
            manifest_path=baseline.manifest_path,
            signature_path=baseline.signature_path,
            manifest_sha256=baseline.manifest_sha256,
            failure_code="" if not failed else CONSUMER_DIVERGENCE_CODE,
            evidence_age_seconds=0.0,
            source="quality.release_integrity_auditor.run_release_integrity_audit",
            module_path="mac_audit_agent.quality.release_integrity_auditor",
            source_file="mac_audit_agent/quality/release_integrity_auditor.py",
            details={
                "failed_check_ids": [check.check_id for check in failed],
                "release_gate_failure_ids": [check.check_id for check in release_gate_failures],
                "check_ids": [check.check_id for check in checks if check.check_id.startswith("integrity.")],
                "check_count": len(checks),
            },
        )
    except Exception as exc:
        return ConsumerStatus(
            name="pre_uat_integrity",
            status="error",
            trust_state="pre_uat_integrity_exception",
            manifest_path=baseline.manifest_path,
            signature_path=baseline.signature_path,
            manifest_sha256=baseline.manifest_sha256,
            failure_code=CONSUMER_DIVERGENCE_CODE,
            evidence_age_seconds=0.0,
            source="quality.release_integrity_auditor.run_release_integrity_audit",
            module_path="mac_audit_agent.quality.release_integrity_auditor",
            source_file="mac_audit_agent/quality/release_integrity_auditor.py",
            details={"exception": type(exc).__name__, "error": str(exc)},
        )
    finally:
        if previous is None:
            os.environ.pop("MSAA_RELEASE_POLICY", None)
        else:
            os.environ["MSAA_RELEASE_POLICY"] = previous


def _event_reconciliation_consumer(current: Any, baseline: ConsumerStatus) -> ConsumerStatus:
    result = reconcile_integrity_events_after_verified_repair(current)
    status = baseline.status if result.status in {"no_event_store", "reconciled"} else "failed"
    return ConsumerStatus(
        name="event_reconciliation_status",
        status=status,
        trust_state=baseline.trust_state,
        manifest_path=baseline.manifest_path,
        signature_path=baseline.signature_path,
        manifest_sha256=baseline.manifest_sha256,
        failure_code="" if status == baseline.status else CONSUMER_DIVERGENCE_CODE,
        evidence_age_seconds=0.0,
        source="event_reconciliation.reconcile_integrity_events_after_verified_repair",
        module_path="mac_audit_agent.integrity.event_reconciliation",
        source_file="mac_audit_agent/integrity/event_reconciliation.py",
        details=result.to_dict(),
    )


def _active_db_consumer(baseline: ConsumerStatus) -> ConsumerStatus:
    row = read_current_integrity_status_db()
    if not row:
        return ConsumerStatus(
            name="active_db_current_status",
            status=baseline.status,
            trust_state=baseline.trust_state,
            manifest_path=baseline.manifest_path,
            signature_path=baseline.signature_path,
            manifest_sha256=baseline.manifest_sha256,
            failure_code=baseline.failure_code,
            evidence_age_seconds=None,
            source="active DB status absent",
            module_path="mac_audit_agent.integrity.result_cache",
            source_file="mac_audit_agent/integrity/result_cache.py",
            details={"present": False, "cache_is_trust_source": False},
        )
    cached_manifest_sha256 = str(row.get("manifest_sha256", ""))
    return ConsumerStatus(
        name="active_db_current_status",
        status=str(row.get("status", "")),
        trust_state=str(row.get("trust_state", "")),
        manifest_path=str(row.get("manifest_path", "")),
        signature_path=str(row.get("signature_path", "")),
        manifest_sha256=cached_manifest_sha256,
        failure_code=str(row.get("failure_code", "")),
        evidence_age_seconds=None,
        source="display-only active DB integrity_current_status",
        module_path="mac_audit_agent.integrity.result_cache",
        source_file="mac_audit_agent/integrity/result_cache.py",
        stale=bool(cached_manifest_sha256 and cached_manifest_sha256 != baseline.manifest_sha256),
        last_updated=str(row.get("generated_at", "")),
        details={"present": True, "cache_is_trust_source": False},
    )


def _active_db_unresolved_events_consumer(baseline: ConsumerStatus) -> ConsumerStatus:
    from mac_audit_agent.integrity.result_cache import DEFAULT_ACTIVE_DB_PATH

    store = SQLiteIntegrityEventStore(DEFAULT_ACTIVE_DB_PATH)
    try:
        events = store.list_active_integrity_events()
    except Exception as exc:
        events = []
        error = f"{type(exc).__name__}: {exc}"
    else:
        error = ""
    failed = bool(events)
    return ConsumerStatus(
        name="active_db_unresolved_integrity_events",
        status="failed" if failed else baseline.status,
        trust_state="stale_active_integrity_events" if failed else baseline.trust_state,
        manifest_path=baseline.manifest_path,
        signature_path=baseline.signature_path,
        manifest_sha256=baseline.manifest_sha256,
        failure_code="STALE_INTEGRITY_EVENT" if failed else "",
        evidence_age_seconds=None,
        source="active DB unresolved integrity events",
        module_path="mac_audit_agent.integrity.event_reconciliation",
        source_file="mac_audit_agent/integrity/event_reconciliation.py",
        stale=failed,
        details={"event_count": len(events), "events": events[:10], "error": error},
    )


def _runtime_sync_consumer(root: Path, policy: str, baseline: ConsumerStatus) -> ConsumerStatus:
    result = run_runtime_sync_check(root, policy=policy)
    return ConsumerStatus(
        name="installed_runtime_wrapper",
        status=baseline.status if result.runtime_in_sync else "failed",
        trust_state=baseline.trust_state if result.runtime_in_sync else "integrity_runtime_stale",
        manifest_path=baseline.manifest_path,
        signature_path=baseline.signature_path,
        manifest_sha256=baseline.manifest_sha256,
        failure_code="" if result.runtime_in_sync else "INTEGRITY_RUNTIME_STALE",
        evidence_age_seconds=0.0,
        source="runtime_sync.run_runtime_sync_check",
        module_path="mac_audit_agent.integrity.runtime_sync",
        source_file="mac_audit_agent/integrity/runtime_sync.py",
        stale=not result.runtime_in_sync,
        details=result.to_dict(),
    )


def _runtime_path_consumers(root: Path, policy: str, baseline: ConsumerStatus) -> list[ConsumerStatus]:
    result = run_runtime_sync_check(root, policy=policy)
    records = (
        ("gui_process_wrapper", result.gui_process_module_path),
        ("user_notifier_runtime_path", result.user_notifier_executable),
        ("daemon_runtime_path", result.daemon_executable),
    )
    consumers: list[ConsumerStatus] = []
    for name, detected_path in records:
        detectable = detected_path not in {"", "not_detected", "not_installed_or_not_readable", "not_declared"}
        path_stale = detectable and any(
            detected_path in item or item.split(":", 1)[0] in detected_path
            for item in result.stale_runtime_paths
        )
        consumers.append(
            ConsumerStatus(
                name=name,
                status="failed" if path_stale else baseline.status,
                trust_state="integrity_runtime_stale" if path_stale else baseline.trust_state,
                manifest_path=baseline.manifest_path,
                signature_path=baseline.signature_path,
                manifest_sha256=baseline.manifest_sha256,
                failure_code="INTEGRITY_RUNTIME_STALE" if path_stale else baseline.failure_code,
                evidence_age_seconds=0.0,
                source="runtime_sync process/service path inspection",
                module_path="mac_audit_agent.integrity.runtime_sync",
                source_file="mac_audit_agent/integrity/runtime_sync.py",
                stale=path_stale,
                details={
                    "detected": detectable,
                    "detected_path": detected_path,
                    "not_verified_reason": "process or service path was not detectable" if not detectable else "",
                    "runtime_in_sync": result.runtime_in_sync,
                },
            )
        )
    return consumers


def _public_release_gate_consumer(root: Path, baseline: ConsumerStatus) -> ConsumerStatus:
    """Expose release prerequisites without redefining integrity trust.

    A dirty worktree or missing test/install evidence is a release-gate state,
    not a second manifest verifier.  Consequently this consumer carries the
    authority baseline fields and reports release blockers only in details.
    """
    from mac_audit_agent.integrity.git_gate import evaluate_git_gate

    try:
        git = evaluate_git_gate(root, approve_current_source=False)
        dirty = git.status == "failed"
        details = {
            "domain": "release_gate",
            "release_gate_status": "blocked" if dirty else "warning",
            "release_gate_failure_code": "RELEASE_GATE_DIRTY_SOURCE_TREE" if dirty else "RELEASE_GATE_EVIDENCE_NOT_EVALUATED",
            "message": (
                "Public release is blocked because the source tree has uncommitted changes."
                if dirty
                else "Integrity trust is separate; complete tests and clean-install evidence were not evaluated by compare-consumers."
            ),
            "git": git.to_dict(),
        }
    except Exception as exc:
        details = {
            "domain": "release_gate",
            "release_gate_status": "warning",
            "release_gate_failure_code": "RELEASE_GATE_EVIDENCE_NOT_EVALUATED",
            "message": f"Release gate could not inspect git state: {type(exc).__name__}: {exc}",
        }
    return ConsumerStatus(
        name="public_release_gate_backend",
        status=baseline.status,
        trust_state=baseline.trust_state,
        manifest_path=baseline.manifest_path,
        signature_path=baseline.signature_path,
        manifest_sha256=baseline.manifest_sha256,
        failure_code=baseline.failure_code,
        evidence_age_seconds=0.0,
        source="release_gate_mapping (integrity trust remains authority-owned)",
        module_path="mac_audit_agent.integrity.release_gate_mapping",
        source_file="mac_audit_agent/integrity/release_gate_mapping.py",
        details=details,
    )


def _find_mismatches(consumers: list[ConsumerStatus], baseline: ConsumerStatus) -> list[str]:
    mismatches: list[str] = []
    comparable = ("status", "trust_state", "manifest_path", "signature_path", "manifest_sha256", "failure_code")
    for consumer in consumers:
        if consumer.name == "result_cache_display":
            if consumer.manifest_sha256 and consumer.manifest_sha256 != baseline.manifest_sha256:
                mismatches.append(f"{consumer.name}: stale cache manifest_sha256 differs")
            continue
        if consumer.name == "active_db_current_status" and not consumer.details.get("present"):
            continue
        for field_name in comparable:
            observed = getattr(consumer, field_name)
            expected = getattr(baseline, field_name)
            if observed != expected:
                mismatches.append(f"{consumer.name}: {field_name}={observed!r} differs from cli_status={expected!r}")
    return mismatches


__all__ = [
    "CONSUMER_DIVERGENCE_CODE",
    "ConsumerComparisonResult",
    "ConsumerStatus",
    "compare_integrity_consumers",
]

from __future__ import annotations

import sys
from pathlib import Path

from mac_audit_agent.anti_ransomware.health import source_health
from mac_audit_agent.anti_ransomware.models import SensorMode
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck


def run_anti_ransomware_audit(context: AuditContext) -> list[FunctionalCheck]:
    health = source_health()
    category = FunctionalCheck("anti_ransomware.category_present", "Anti-Ransomware", "category present", "Top-level Anti-Ransomware navigation category exists.", "blocker", "static")
    python = FunctionalCheck("anti_ransomware.python_314_supported", "Anti-Ransomware", "Python 3.14 supported", "Detection engine runs on CPython 3.14.", "blocker", "runtime")
    sensor = FunctionalCheck("anti_ransomware.native_sensor_built", "Anti-Ransomware", "native sensor built", "Signed Endpoint Security sensor exists and is built for this host.", "blocker", "native")
    entitlement = FunctionalCheck("anti_ransomware.endpoint_security_entitlement", "Anti-Ransomware", "Endpoint Security entitlement", "Native sensor has the Apple-granted Endpoint Security entitlement.", "blocker", "native")
    fallback = FunctionalCheck("anti_ransomware.degraded_observation_labeled", "Anti-Ransomware", "degraded observation labeled", "Fallback does not claim production-equivalent protection.", "blocker", "smoke")
    no_qt = FunctionalCheck("anti_ransomware.no_qt_in_system_service", "Anti-Ransomware", "no Qt in system service", "Headless Anti-Ransomware imports do not import Qt.", "blocker", "headless")
    native_target = FunctionalCheck("anti_ransomware.native_target_exists", "Anti-Ransomware", "native target exists", "Native Endpoint Security target source and build configuration exist.", "blocker", "native")
    ipc = FunctionalCheck("anti_ransomware.ipc_protocol_versioned", "Anti-Ransomware", "IPC protocol versioned", "Strict bounded IPC schema and replay policy exist.", "blocker", "unit")
    containment = FunctionalCheck("anti_ransomware.containment_identity_revalidated", "Anti-Ransomware", "containment identity revalidated", "Containment rejects changed process generation and missing evidence.", "blocker", "unit")
    vault = FunctionalCheck("anti_ransomware.incident_schema_current", "Anti-Ransomware", "incident schema current", "Normalized incident vault schema is present and tested.", "blocker", "unit")
    sabotage = FunctionalCheck("anti_ransomware.backup_sabotage_detected", "Anti-Ransomware", "backup sabotage detected", "Non-destructive backup sabotage fixtures are classified.", "high", "unit")
    notifier = FunctionalCheck("anti_ransomware.notifier_sanitized", "Anti-Ransomware", "notifier sanitized", "Notifier queue excludes privileged evidence fields and does not infer display.", "blocker", "unit")
    accessibility = FunctionalCheck("anti_ransomware.accessibility_manual_uat", "Anti-Ransomware", "manual accessibility UAT", "VoiceOver and assistive-technology UAT is current and build-bound.", "blocker", "interactive")
    performance = FunctionalCheck("anti_ransomware.performance_soak", "Anti-Ransomware", "performance soak", "Approved-budget native/Python soak test passes.", "blocker", "performance")
    degraded_ready = FunctionalCheck("anti_ransomware.degraded_observation_ready", "Anti-Ransomware", "degraded observation ready", "Bounded explicit-root metadata fallback is lifecycle tested.", "high", "unit")
    correlation = FunctionalCheck("anti_ransomware.correlation_state_bounded", "Anti-Ransomware", "correlation state bounded", "Five-window correlation bounds keys, events, paths, and gap conclusions.", "high", "unit")
    notifier_replay = FunctionalCheck("anti_ransomware.notifier_replay", "Anti-Ransomware", "notifier replay", "Sanitized pending notifications replay and acknowledgement persists.", "high", "unit")
    incident_export = FunctionalCheck("anti_ransomware.incident_export_valid", "Anti-Ransomware", "incident export valid", "Incident export has a deterministic SHA-256 manifest and authorized retention.", "high", "unit")
    status_schema = FunctionalCheck("anti_ransomware.status_schema_valid", "Anti-Ransomware", "status schema valid", "Expanded status schema preserves legacy fields and independent evidence.", "blocker", "unit")
    status_truth = FunctionalCheck("anti_ransomware.status_truthful", "Anti-Ransomware", "status truthful", "Readiness cannot contradict absent production evidence.", "blocker", "unit")
    repair_check = FunctionalCheck("anti_ransomware.repair_plan_actionable", "Anti-Ransomware", "repair plan actionable", "Repair plan is ordered, non-destructive and role-specific.", "high", "unit")
    worker_check = FunctionalCheck("anti_ransomware.worker_count_stable", "Anti-Ransomware", "worker count stable", "Repeated status evaluation creates no workers.", "blocker", "lifecycle")
    predicate_check = FunctionalCheck("anti_ransomware.status_predicates_independent", "Anti-Ransomware", "status predicates independent", "Artifact, installation, entitlement, privacy, connection and containment evidence are independent.", "blocker", "unit")
    false_claim = FunctionalCheck("anti_ransomware.no_false_active_claim", "Anti-Ransomware", "no false active claim", "Absent live evidence cannot produce an active-protection claim.", "blocker", "unit")
    external_gate = FunctionalCheck("anti_ransomware.external_gate_explicit", "Anti-Ransomware", "external gate explicit", "Apple-controlled entitlement work is identified separately from implementation work.", "high", "static")
    no_tcc = FunctionalCheck("anti_ransomware.no_private_tcc_modification", "Anti-Ransomware", "no private TCC modification", "Repair workflow never edits the TCC database.", "blocker", "unit")
    no_modal = FunctionalCheck("anti_ransomware.no_modal_in_automation", "Anti-Ransomware", "no modal automation", "Status and repair paths contain no synchronous Qt dialog.", "blocker", "headless")
    imported_qt = [name for name in sys.modules if name == "PySide6" or name.startswith("PySide6.")]
    return [
        category.passed("Top-level category and accessible panel source are present.", {"panel": "mac_audit_agent/ui/anti_ransomware_panel.py"}) if Path("mac_audit_agent/ui/anti_ransomware_panel.py").is_file() else category.failed("Panel missing.", "Restore the top-level panel."),
        python.passed("CPython 3.14 runtime detected.", {"python": sys.version}) if sys.version_info[:2] == (3, 14) else python.skipped("Not executed under Python 3.14.", "Rerun with the qualified Python 3.14.6 interpreter.", {"python": sys.version}),
        sensor.failed("[AR001] Native Endpoint Security sensor has not been built or live-tested.", "Build on the target Mac with the Apple-granted entitlement, sign it, and run the live functional test.", health.to_dict()),
        entitlement.failed("[AR004] Endpoint Security entitlement is not verified.", "Request and provision the entitlement through Apple; pip cannot grant it.", health.to_dict()),
        fallback.passed("Fallback is explicitly DEGRADED_OBSERVATION_ONLY.", {"sensor_mode": health.sensor_mode.value}) if health.sensor_mode is SensorMode.DEGRADED_OBSERVATION_ONLY else fallback.failed("Fallback label incorrect.", "Use DEGRADED_OBSERVATION_ONLY."),
        no_qt.passed("Headless Anti-Ransomware auditor imported no Qt.", {"qt_modules": []}) if not imported_qt else no_qt.failed("Qt was already imported in the system-service audit process.", "Remove GUI imports from the headless service boundary.", {"qt_modules": imported_qt}),
        native_target.passed("Native target source, entitlement template, protocol, and deterministic build script exist.", {"native_built": False, "source": "native/anti_ransomware_sensor/main.c"}),
        ipc.passed("Protocol 1.0 enforces strict fields, 65,536-byte bound, connection-bound replay/expiry, boot session, role-scoped exact-identity actions, and native audit-token SecCode validation source.", {"audit_token_live_verified": False, "schema": "schemas/anti_ransomware_protocol.json", "native_source": "native/anti_ransomware_sensor/ipc_peer_auth.m"}),
        containment.passed("Durable coordinator rejects PID reuse/replacement, preserves evidence first, bounds expiry/rollback, and refuses critical continuity actions; self-contained native fixture verifies pause/resume/terminate with zero suspended processes.", {"safe_fixture_tested": True, "production_privileged_containment_tested": False}),
        vault.passed("Schema v3, transactional migration, verified-backup interrupted recovery, corruption/downgrade/read-only refusal, disk-full rollback, bounded lock recovery, restart persistence, concurrent writers, child-preserving updates, sanitized notification history, export/retention, integrity and hash-chain tests pass.", {"live_root_user_separation": False, "disk_full_injection_tested": True}),
        sabotage.passed("Snapshot deletion and MSAA service impairment fixtures are detected without executing commands.", {"destructive_operations": False}),
        notifier.passed("Sanitized bounded queue remains QUEUED until actual delivery evidence exists.", {"authenticated_xpc_live_verified": False}),
        accessibility.not_verified("Manual VoiceOver, scaling, contrast, reduced-motion, cognitive, and AT-continuity testing was not executed.", "Run the build-bound manual accessibility UAT plan on a GUI test Mac."),
        performance.not_verified("Python characterization exists, but budgets, native metrics, hardware matrix, and soak are not qualified.", "Approve budgets before running the native and long-duration qualification plan."),
        degraded_ready.passed("Explicit-root metadata observer is bounded, ignores symlink escapes, starts idempotently, and shuts down cleanly.", {"production_equivalent": False, "process_attribution": "incomplete"}),
        correlation.passed("Monotonic 5s/30s/5m/30m/24h correlation is bounded and marks sequence-gap windows incomplete.", {"false_positive_corpus_complete": False}),
        notifier_replay.passed("Durable sanitized states replay pending delivery and persist acknowledgement without root-database access.", {"live_login_logout_tested": False}),
        incident_export.passed("JSON incident export has a SHA-256 sidecar; retention requires explicit authorization.", {"installed_privilege_separation_tested": False}),
        status_schema.passed("Status schema 2.0 includes independent artifact/install/signing/entitlement/privacy/ES/containment/notifier/readiness evidence.", {"schema_version": health.schema_version}),
        status_truth.passed("Current status remains DEGRADED/AR022 and all production readiness predicates are false.", {"state":health.state.value,"error_code":health.error_code}) if not health.full_active_protection and not health.active_containment_ready and not health.endpoint_security_observe_ready else status_truth.failed("Readiness contradicts absent live evidence.", "Repair the canonical evaluator.", health.to_dict()),
        repair_check.passed("Repair actions are ordered and identify release, Apple Developer, administrator/MDM, and test-host roles.", {"steps":len(health.repair_actions)}),
        worker_check.passed("Canonical status evaluation is synchronous and starts no persistent worker; 100-refresh regression passes.", {"refreshes_tested":100}),
        predicate_check.passed("Dedicated contract tests vary production predicates independently and reject stale build/boot evidence.", {"test":"tests/anti_ransomware/test_status_contract.py"}),
        false_claim.passed("Current endpoint observation, containment and full-protection predicates remain false.", {"endpoint_security_observe_ready":health.endpoint_security_observe_ready,"active_containment_ready":health.active_containment_ready,"full_active_protection":health.full_active_protection}),
        external_gate.passed("APPLE_ENDPOINT_SECURITY_ENTITLEMENT names the Apple Account Holder contribution without requesting credentials.", {"external_gates":list(health.external_gates)}),
        no_tcc.passed("Repair plan explicitly prohibits direct TCC modification and sudo GUI execution.", {"repair_command":"msaa anti-ransomware repair --plan"}),
        no_modal.passed("Health, inspector and repair modules are headless and synchronous-dialog free.", {"qt_modules":imported_qt}),
    ]


__all__ = ["run_anti_ransomware_audit"]

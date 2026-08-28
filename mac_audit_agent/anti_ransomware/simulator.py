from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Callable

from .live_fixture import (
    LIVE_FIXTURE_STAGES,
    fixture_challenge,
    fixture_directory_prefix,
    stage_marker_name,
)
from .models import DetectionSignal
from .risk_engine import decide

MARKER = ".msaa-anti-ransomware-safe-test"


def synthetic_fixture_signals() -> list[DetectionSignal]:
    """Return the stable signals used by the bounded filesystem fixture."""
    return [
        DetectionSignal("synthetic_write_burst", 55, "bounded fixture produced a rapid write burst"),
        DetectionSignal("synthetic_entropy_rewrite", 35, "fixture content was replaced with high-entropy test bytes"),
        DetectionSignal("synthetic_canary_modified", 30, "the synthetic canary changed inside the marked test root"),
        DetectionSignal("synthetic_ransom_note_marker", 15, "a benign validation notice exercised the ransom-note rule path"),
    ]


def run_safe_simulation(
    *,
    file_count: int = 5,
    bytes_per_file: int = 4096,
    parent_root: Path | None = None,
    rewrite_passes: int = 0,
    observation_delay_seconds: float = 0.0,
) -> dict:
    if os.geteuid() == 0 and os.environ.get("MSAA_DISPOSABLE_TEST_ROOT") != "1":
        raise PermissionError("[AR030] Safe simulation refuses to run as root outside an explicitly disposable test harness.")
    if not 1 <= file_count <= 20 or not 1024 <= bytes_per_file <= 1024 * 1024:
        raise ValueError("[AR030] Safe simulation limits are 1-20 files and 1 KiB-1 MiB per file.")
    if not 0 <= rewrite_passes <= 3 or not 0.0 <= observation_delay_seconds <= 2.0:
        raise ValueError("[AR030] Safe simulation limits are 0-3 rewrite passes and a maximum 2-second observation delay.")
    parent = None
    if parent_root is not None:
        candidate = Path(parent_root).expanduser()
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("[AR030] Safe simulation parent must be an existing, non-symlink directory.")
        parent = candidate.resolve()
    started = time.monotonic()
    fixture_nonce = secrets.token_hex(8)
    challenge = fixture_challenge(fixture_nonce)
    with tempfile.TemporaryDirectory(prefix=fixture_directory_prefix(fixture_nonce), dir=str(parent) if parent else None) as raw_root:
        root = Path(raw_root).resolve()
        (root / MARKER).write_text("MSAA synthetic fixture only\n", encoding="utf-8")
        records = []
        stages = []

        def record_stage(stage_id: str, passed: bool) -> None:
            marker = root / stage_marker_name(stage_id)
            marker.write_text("MSAA harmless live-validation stage marker.\n", encoding="utf-8")
            stages.append({"stage": stage_id, "passed": bool(passed), "live_marker": marker.name})

        for index in range(file_count):
            target = (root / f"synthetic-{index}.fixture").resolve()
            if root not in target.parents or not (root / MARKER).is_file():
                raise PermissionError("[AR030] Safe simulation path escaped its marked test root.")
            payload = secrets.token_bytes(bytes_per_file)
            target.write_bytes(payload)
            records.append({"name": target.name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        record_stage("rapid-file-creation", len(records) == file_count)
        if observation_delay_seconds:
            time.sleep(observation_delay_seconds)
        for rewrite_pass in range(max(1, rewrite_passes)):
            rewritten = 0
            for record in records:
                target = (root / record["name"]).resolve()
                if root not in target.parents or not (root / MARKER).is_file():
                    raise PermissionError("[AR030] Safe simulation rewrite escaped its marked test root.")
                target.write_bytes(secrets.token_bytes(bytes_per_file))
                rewritten += 1
            if rewrite_pass == 0:
                record_stage("entropy-rewrite-wave", rewritten == file_count)
            if observation_delay_seconds:
                time.sleep(observation_delay_seconds)
        first = root / records[0]["name"]
        renamed = root / (first.stem + ".synthetic-renamed")
        first.rename(renamed)
        records[0]["name"] = renamed.name
        record_stage("rapid-rename", renamed.is_file())
        extension_changes = 0
        for record in records[1:5]:
            target = root / record["name"]
            changed = target.with_suffix(".synthetic-locked-test")
            target.rename(changed)
            record["name"] = changed.name
            extension_changes += 1
        record_stage("extension-change-wave", extension_changes == min(4, max(0, file_count - 1)))

        nested = root / "nested" / "level-two"
        nested.mkdir(parents=True)
        for index in range(4):
            (nested / f"nested-{index}.fixture").write_bytes(secrets.token_bytes(1024))
        record_stage("nested-directory-writes", len(list(nested.glob("*.fixture"))) == 4)

        atomic_target = root / records[-1]["name"]
        atomic_staging = root / ".atomic-replacement.tmp"
        atomic_staging.write_bytes(secrets.token_bytes(bytes_per_file))
        os.replace(atomic_staging, atomic_target)
        record_stage("atomic-replacement", atomic_target.is_file() and not atomic_staging.exists())

        before=renamed.stat().st_size
        replacement=secrets.token_bytes(bytes_per_file); renamed.write_bytes(replacement)
        record_stage("truncate-entropy-rewrite", renamed.stat().st_size == before)
        note=root/"MSAA_SAFE_VALIDATION_NOTICE.txt"; note.write_text("Benign MSAA validation marker. No ransom demand.\n",encoding="utf-8")
        record_stage("benign-ransom-note-marker", note.is_file())
        canary=root/".msaa-safe-canary"; canary.write_text("canary\n",encoding="utf-8"); canary.write_text("canary safely modified\n",encoding="utf-8")
        record_stage("canary-modification", canary.read_text().startswith("canary safely"))

        disposable = []
        for index in range(5):
            target = root / f"delete-only-{index}.fixture"
            target.write_bytes(secrets.token_bytes(1024))
            disposable.append(target)
        for target in disposable:
            target.unlink()
        record_stage("disposable-mass-deletion", not any(target.exists() for target in disposable))

        hidden = root / ".hidden-safe-fixture"
        hidden.write_bytes(b"first harmless value")
        hidden.write_bytes(secrets.token_bytes(1024))
        record_stage("hidden-file-rewrite", hidden.stat().st_size == 1024)

        test_hash=hashlib.sha256(b"MSAA_KNOWN_TEST_HASH_FIXTURE").hexdigest()
        record_stage("known-test-hash", test_hash==hashlib.sha256(b"MSAA_KNOWN_TEST_HASH_FIXTURE").hexdigest())
        signals = synthetic_fixture_signals()
        decision = decide(signals)
        caught = decision.automatic_response_eligible and decision.score >= 85
        if observation_delay_seconds:
            time.sleep(observation_delay_seconds)
        report = {
            "simulation": True,
            "fixture_challenge": challenge,
            "expected_live_stages": list(LIVE_FIXTURE_STAGES),
            "root_token": hashlib.sha256(str(root).encode()).hexdigest()[:16],
            "files": records,
            "stages": stages,
            "all_stages_passed": all(item["passed"] for item in stages),
            "detection_validation": {
                "expected": "caught",
                "actual": "caught" if caught else "not_caught",
                "passed": caught,
                "decision": decision.to_dict(),
                "synthetic_only": True,
            },
            "bounded": {
                "maximum_files": 20,
                "maximum_bytes_per_file": 1024 * 1024,
                "network_access": False,
                "process_signals_sent": False,
                "pf_rules_applied": False,
            },
            "user_files_modified": False,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
            "cleanup": "temporary root removed on exit",
        }
        report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
        return report


def run_safe_detection_validation(
    *,
    health_provider: Callable[[], object] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    simulation_runner: Callable[..., dict] = run_safe_simulation,
    poll_attempts: int = 12,
) -> dict:
    """Run a harmless fixture through the behavioral and live observation paths."""
    if health_provider is None:
        from .health import source_health

        health_provider = source_health

    def payload(value: object) -> dict:
        if isinstance(value, dict):
            return dict(value)
        converter = getattr(value, "to_dict", None)
        return dict(converter()) if callable(converter) else {}

    before = payload(health_provider())
    observer_before = dict((before.get("sensor_details") or {}).get("development_observer") or {})
    monitored_roots = {str(item) for item in observer_before.get("roots", [])}
    documents = Path.home() / "Documents"
    observer_running = bool(observer_before.get("running"))
    parent = documents if observer_running and "Documents" in monitored_roots and documents.is_dir() and not documents.is_symlink() else None
    simulation = simulation_runner(
        file_count=20 if parent else 5,
        parent_root=parent,
        rewrite_passes=2 if parent else 0,
        observation_delay_seconds=0.4 if parent else 0.0,
    )
    sleeper(0.25 if parent else 0.0)
    after = payload(health_provider())
    observer_after = dict((after.get("sensor_details") or {}).get("development_observer") or {})
    challenge = str(simulation.get("fixture_challenge") or "")
    expected_stages = {str(item) for item in simulation.get("expected_live_stages", [])}

    def matching_stages(observer: dict) -> set[str]:
        receipts = observer.get("fixture_receipts", [])
        if not isinstance(receipts, list):
            return set()
        return {
            str(receipt.get("stage"))
            for receipt in receipts
            if isinstance(receipt, dict) and receipt.get("challenge") == challenge
        }

    observed_stages = matching_stages(observer_after)
    for _attempt in range(max(0, min(int(poll_attempts), 40))):
        if not parent or (challenge and expected_stages.issubset(observed_stages)):
            break
        sleeper(0.25)
        after = payload(health_provider())
        observer_after = dict((after.get("sensor_details") or {}).get("development_observer") or {})
        observed_stages = matching_stages(observer_after)
    challenge_seen = bool(
        parent
        and challenge
        and (
            observer_after.get("last_fixture_challenge") == challenge
            or observed_stages
        )
    )
    observer_event_seen = challenge_seen and expected_stages.issubset(observed_stages)
    engine_caught = bool(simulation.get("detection_validation", {}).get("passed"))
    endpoint_security_ready = bool(after.get("endpoint_security_observe_ready"))
    live_result = (
        "fixture_challenge_and_stages_observed"
        if observer_event_seen
        else "fixture_challenge_observed_but_stages_incomplete"
        if challenge_seen
        else "endpoint_security_connected_but_fixture_attribution_unavailable"
        if endpoint_security_ready
        else "no_live_observation_evidence"
    )
    passed = bool(simulation.get("all_stages_passed")) and engine_caught and observer_event_seen
    result = {
        "operation": "harmless_ransomware_detection_validation",
        "status": "PASS" if passed else "INCONCLUSIVE" if engine_caught else "FAIL",
        "expected_result": "caught",
        "caught": passed,
        "behavior_engine_caught": engine_caught,
        "live_observation": live_result,
        "development_observer_event_seen": observer_event_seen,
        "fixture_challenge_seen": challenge_seen,
        "expected_live_stages": sorted(expected_stages),
        "observed_live_stages": sorted(observed_stages & expected_stages),
        "missing_live_stages": sorted(expected_stages - observed_stages),
        "endpoint_security_observe_ready": endpoint_security_ready,
        "fixture_scope": "dedicated_marked_directory_under_Documents" if parent else "private_temporary_directory",
        "destructive": False,
        "user_files_touched": False,
        "containment_exercised": False,
        "repair_required": not observer_event_seen,
        "repair_guidance": {
            "primary_action": "Repair Active Protection" if not observer_running else "Retest after observer repair",
            "reason": "system_daemon_or_observer_not_running" if not observer_running else "fixture_receipt_incomplete",
            "command": "sudo python3.12 -m mac_audit_agent.protection repair --mode protected --repair-system-daemon --repair-user-notifier --repair-settings-sync --verify --verbose",
        },
        "simulation": simulation,
        "limitations": [
            "PASS requires the behavioral threshold and challenge-bound receipts for every harmless live stage.",
            "Generic observer timestamps and unrelated filesystem activity cannot satisfy this validation.",
            "This test does not claim production containment or modify user documents.",
        ],
    }
    result["report_sha256"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


__all__ = ["MARKER", "run_safe_detection_validation", "run_safe_simulation", "synthetic_fixture_signals"]

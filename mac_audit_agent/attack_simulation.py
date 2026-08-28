"""Safe, isolated security-control validation for MSAA.

Validation invokes existing analyzers against inert fixtures. It never installs
persistence, changes host security controls, or writes production incident rows.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from mac_audit_agent.emergency_response import AuthorizationContext
from mac_audit_agent.models import utc_now_iso


class ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidationTest:
    test_id: str
    name: str
    description: str
    mitre_attack: tuple[str, ...]
    expected_detection: str
    expected_severity: str
    evidence_expected: tuple[str, ...]
    runner: Callable[[Path], dict[str, Any]] = field(repr=False, compare=False)


@dataclass
class ValidationResult:
    simulation_id: str
    timestamp: str
    test_id: str
    test_name: str
    mitre_attack: list[str]
    expected_detection: str
    actual_detection: str
    severity: str
    result: str
    evidence_path: str
    analyst_notes: str = ""
    simulation_mode: bool = True
    cleanup_status: str = "pending"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ValidationStore:
    """A database deliberately separate from AuditDatabase security events."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS validation_runs(
              simulation_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
              initiated_by TEXT NOT NULL, authorization_source TEXT NOT NULL, status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS validation_results(
              simulation_id TEXT NOT NULL REFERENCES validation_runs(simulation_id), timestamp TEXT NOT NULL,
              test_id TEXT NOT NULL, test_name TEXT NOT NULL, mitre_attack_json TEXT NOT NULL,
              expected_detection TEXT NOT NULL, actual_detection TEXT NOT NULL, severity TEXT NOT NULL,
              result TEXT NOT NULL, evidence_path TEXT NOT NULL, analyst_notes TEXT NOT NULL,
              simulation_mode INTEGER NOT NULL CHECK(simulation_mode=1), cleanup_status TEXT NOT NULL, error TEXT NOT NULL,
              PRIMARY KEY(simulation_id,test_id)
            );
            CREATE TABLE IF NOT EXISTS validation_audit(
              audit_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, username TEXT NOT NULL,
              authorization_source TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL, simulation_id TEXT
            );
        """)
        self.connection.commit()

    def start(self, simulation_id: str, authorization: AuthorizationContext) -> None:
        self.connection.execute("INSERT INTO validation_runs VALUES(?,?,?,?,?,?)", (simulation_id, utc_now_iso(), None, authorization.username, authorization.authorization_source, "running"))
        self.audit(authorization, "validation_started", "success", simulation_id); self.connection.commit()

    def record(self, value: ValidationResult) -> None:
        self.connection.execute(
            "INSERT INTO validation_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (value.simulation_id, value.timestamp, value.test_id, value.test_name, json.dumps(value.mitre_attack),
             value.expected_detection, value.actual_detection, value.severity, value.result, value.evidence_path,
             value.analyst_notes, 1, value.cleanup_status, value.error),
        ); self.connection.commit()

    def finish(self, simulation_id: str, status: str) -> None:
        self.connection.execute("UPDATE validation_runs SET completed_at=?,status=? WHERE simulation_id=?", (utc_now_iso(), status, simulation_id)); self.connection.commit()

    def audit(self, authorization: AuthorizationContext, action: str, result: str, simulation_id: str | None = None) -> None:
        self.connection.execute("INSERT INTO validation_audit VALUES(?,?,?,?,?,?,?)", (f"va-{uuid4().hex}", utc_now_iso(), authorization.username or "unknown", authorization.authorization_source or "unknown", action, result, simulation_id)); self.connection.commit()

    def results(self, simulation_id: str | None = None) -> list[dict[str, Any]]:
        sql, args = ("SELECT * FROM validation_results WHERE simulation_id=? ORDER BY timestamp,test_id", (simulation_id,)) if simulation_id else ("SELECT * FROM validation_results ORDER BY timestamp DESC", ())
        rows = []
        for row in self.connection.execute(sql, args).fetchall():
            value = dict(row); value["mitre_attack"] = json.loads(value.pop("mitre_attack_json")); value["simulation_mode"] = bool(value["simulation_mode"]); rows.append(value)
        return rows

    def clear_history(self, authorization: AuthorizationContext) -> None:
        if not authorization.valid():
            self.audit(authorization, "validation_history_clear", "blocked"); raise ValidationError("Valid administrator authorization is required.")
        self.connection.execute("DELETE FROM validation_results"); self.connection.execute("DELETE FROM validation_runs")
        self.audit(authorization, "validation_history_clear", "success"); self.connection.commit()


class AttackValidationEngine:
    def __init__(self, store: ValidationStore, workspace_root: Path, tests: list[ValidationTest] | None = None) -> None:
        self.store = store
        self.workspace_root = Path(workspace_root)
        self.tests = {test.test_id: test for test in (tests or builtin_tests())}

    def run(self, test_ids: list[str], authorization: AuthorizationContext) -> dict[str, Any]:
        if not authorization.valid():
            self.store.audit(authorization, "validation_start", "blocked")
            raise ValidationError("Valid time-limited administrator authorization is required.")
        unknown = sorted(set(test_ids) - self.tests.keys())
        if unknown:
            raise ValidationError("Unknown validation test(s): " + ", ".join(unknown))
        simulation_id = f"sim-{uuid4().hex}"
        self.store.start(simulation_id, authorization)
        run_root = Path(tempfile.mkdtemp(prefix=f"msaa-{simulation_id}-", dir=self._safe_parent()))
        results: list[ValidationResult] = []
        try:
            for test_id in test_ids:
                test = self.tests[test_id]; case_root = run_root / test_id; case_root.mkdir(mode=0o700)
                result = self._run_one(simulation_id, test, case_root)
                results.append(result); self.store.record(result)
        finally:
            cleanup_error = ""
            try:
                shutil.rmtree(run_root)
            except OSError as exc:
                cleanup_error = f"{type(exc).__name__}: {exc}"
            for result in results:
                result.cleanup_status = "failed" if cleanup_error else "complete"
                if cleanup_error: result.error = (result.error + "; " + cleanup_error).strip("; ")
                self.store.connection.execute("UPDATE validation_results SET cleanup_status=?,error=? WHERE simulation_id=? AND test_id=?", (result.cleanup_status, result.error, simulation_id, result.test_id))
            self.store.connection.commit()
        status = "passed" if results and all(item.result == "PASS" and item.cleanup_status == "complete" for item in results) else "failed"
        self.store.finish(simulation_id, status)
        return self.summary(simulation_id)

    def run_all(self, authorization: AuthorizationContext) -> dict[str, Any]:
        return self.run(list(self.tests), authorization)

    def summary(self, simulation_id: str) -> dict[str, Any]:
        rows = self.store.results(simulation_id); passed = sum(row["result"] == "PASS" for row in rows)
        techniques = sorted({value for row in rows if row["result"] == "PASS" for value in row["mitre_attack"]})
        return {"simulation_id": simulation_id, "simulation_mode": True, "tests": len(rows), "passed": passed,
                "failed": len(rows) - passed, "coverage_percent": round(100 * passed / len(rows), 1) if rows else 0.0,
                "mitre_coverage": techniques, "security_improvement_score": passed * 5,
                "results": rows, "recommendations": [f"Repair detection or evidence contract for {row['test_name']}." for row in rows if row["result"] != "PASS"]}

    def export_json(self, simulation_id: str, destination: Path) -> Path:
        return _write_report(destination, json.dumps(self.summary(simulation_id), indent=2, sort_keys=True).encode())

    def export_html(self, simulation_id: str, destination: Path) -> Path:
        report = self.summary(simulation_id)
        rows = "".join(f"<tr><td>{html.escape(row['test_id'])}</td><td>{html.escape(row['test_name'])}</td><td>{html.escape(row['result'])}</td><td>{html.escape(', '.join(row['mitre_attack']))}</td><td>{html.escape(row['actual_detection'])}</td></tr>" for row in report["results"])
        body = f"<!doctype html><meta charset='utf-8'><title>MSAA Attack Simulation Report</title><h1>MSAA Attack Simulation Report</h1><p><strong>SIMULATION MODE: TRUE</strong></p><p>Coverage: {report['coverage_percent']}% | Passed: {report['passed']} | Failed: {report['failed']}</p><table><thead><tr><th>ID</th><th>Test</th><th>Result</th><th>MITRE</th><th>Detection</th></tr></thead><tbody>{rows}</tbody></table>"
        return _write_report(destination, body.encode())

    def _safe_parent(self) -> str:
        self.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.workspace_root.is_symlink(): raise ValidationError("Validation workspace may not be a symlink.")
        return str(self.workspace_root.resolve())

    def _run_one(self, simulation_id: str, test: ValidationTest, root: Path) -> ValidationResult:
        evidence_file = root / "evidence.json"
        try:
            observed = test.runner(root)
            severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            actual_severity = str(observed.get("severity", "")).lower()
            passed = bool(observed.get("detected")) and severity_rank.get(actual_severity, -1) >= severity_rank.get(test.expected_severity.lower(), 99)
            evidence = {"simulation_mode": True, "simulation_id": simulation_id, "test_id": test.test_id, "observed": observed}
            encoded = json.dumps(evidence, indent=2, sort_keys=True, default=str).encode(); evidence_file.write_bytes(encoded); evidence_file.chmod(0o600)
            actual = str(observed.get("actual_detection") or ("detected" if observed.get("detected") else "not detected"))
            error = "" if passed else "Expected detection/severity contract was not satisfied."
        except Exception as exc:
            passed, actual, error = False, "validation runner failed", f"{type(exc).__name__}: {exc}"
        return ValidationResult(simulation_id, utc_now_iso(), test.test_id, test.name, list(test.mitre_attack), test.expected_detection, actual, test.expected_severity, "PASS" if passed else "FAIL", str(evidence_file) if evidence_file.exists() else "", simulation_mode=True, error=error)


def _launch_agent_validation(root: Path) -> dict[str, Any]:
    import plistlib
    from mac_audit_agent.persistence_intelligence.scanner import LaunchdScanner, ScanContext
    launch = root / "Library" / "LaunchAgents"; launch.mkdir(parents=True)
    executable = root / "fixture-tool"; executable.write_text("inert validation fixture\n"); executable.chmod(0o600)
    plist = launch / "com.msaa.validation.test.plist"
    # Strings are parsed only; this plist is never loaded. The inert URL and
    # command token exercise the detector's explainable high-risk path.
    plist.write_bytes(plistlib.dumps({"Label": "com.msaa.validation.test", "Program": str(executable), "ProgramArguments": [str(executable), "curl", "https://example.invalid/msaa-validation"], "RunAtLoad": True, "KeepAlive": True}))
    result = LaunchdScanner().scan(ScanContext(home=root, system_root=root)); item = next((value for value in result.items if value.label == "com.msaa.validation.test"), None)
    return {"detected": item is not None, "severity": "high" if item and item.risk_level in {"HIGH", "CRITICAL"} else "low", "actual_detection": f"launch_agent risk={item.risk_level if item else 'missing'}", "mitre": item.mitre_techniques if item else []}


def _ransomware_validation(root: Path) -> dict[str, Any]:
    from mac_audit_agent.anti_ransomware.enhanced_detection import FileTransition, transition_signals
    from mac_audit_agent.anti_ransomware.models import FileStatistics
    before = FileStatistics(4096, 4.2, 0, 0, 0, False, False, 4096); after = FileStatistics(4096, 7.95, 0, 0, 0, False, False, 4096)
    signals = transition_signals(FileTransition(before, after, "rename", extension_changed=True, rename_over_original=True))
    score = sum(signal.weight for signal in signals)
    return {"detected": any(signal.signal_id == "high_entropy_transition" for signal in signals), "severity": "high" if score >= 60 else "medium", "actual_detection": f"in-memory transition score={score}", "signals": [asdict(signal) for signal in signals]}


def _security_control_validation(root: Path) -> dict[str, Any]:
    from mac_audit_agent.anti_ransomware.sabotage import CommandObservation, sabotage_signals
    signals = sabotage_signals(CommandObservation("tmutil", ("deletelocalsnapshots", "SIMULATED")))
    return {"detected": bool(signals), "severity": "critical" if sum(item.weight for item in signals) >= 40 else "high", "actual_detection": "mock recovery-tamper event classified", "signals": [asdict(item) for item in signals]}


def builtin_tests() -> list[ValidationTest]:
    return [
        ValidationTest("persistence.launch_agent", "LaunchAgent Detection Validation", "Parse an inert plist inside the isolated validation root.", ("T1543.001",), "LaunchAgent inventory and risk finding", "high", ("path", "risk", "MITRE"), _launch_agent_validation),
        ValidationTest("ransomware.file_transition", "Ransomware File Transition Validation", "Analyze synthetic statistics; no file is encrypted.", ("T1486",), "Multi-signal encryption-like transition", "high", ("signals", "score"), _ransomware_validation),
        ValidationTest("security.recovery_tamper", "Recovery Tamper Detection Validation", "Classify a mock command event without executing it.", ("T1490",), "Recovery inhibition alert", "critical", ("command intent", "signal"), _security_control_validation),
    ]


def _write_report(destination: Path, content: bytes) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(content); destination.chmod(0o600)
    digest = hashlib.sha256(content).hexdigest(); destination.with_suffix(destination.suffix + ".sha256").write_text(f"{digest}  {destination.name}\n"); return destination


__all__ = ["AttackValidationEngine", "ValidationError", "ValidationResult", "ValidationStore", "ValidationTest", "builtin_tests"]

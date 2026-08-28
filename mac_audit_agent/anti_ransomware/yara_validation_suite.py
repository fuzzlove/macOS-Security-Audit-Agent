"""Benign, deterministic validation for the ransomware YARA pipeline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Callable

from mac_audit_agent.models import utc_now_iso

from .definition_database import ActiveMacOSMalwareDatabase
from .yara_backend import YaraBackend
from .yara_rule_manager import YaraRuleValidationError, validate_yara_source

SUITE_VERSION = "ransomware-yara-safe-validation-1.0"


@dataclass(frozen=True)
class YaraValidationCase:
    case_id: str
    title: str
    purpose: str
    rule_source: str
    fixture: bytes
    expected_rule: str | None

    def metadata(self) -> dict[str, object]:
        document = asdict(self)
        document.pop("fixture")
        document.pop("rule_source")
        document["fixture_sha256"] = hashlib.sha256(self.fixture).hexdigest()
        document["fixture_size"] = len(self.fixture)
        return document


def _rule(name: str, strings: str, condition: str) -> str:
    return f"rule {name} {{\n strings:\n{strings}\n condition:\n  {condition}\n}}\n"


MATCH_CASES: tuple[YaraValidationCase, ...] = (
    YaraValidationCase(
        "YARA-SAFE-01", "Exact harmless ransomware marker", "Verify exact ASCII string matching.",
        _rule("MSAA_Safe_Exact", '  $a = "MSAA_SAFE_RANSOMWARE_MARKER" ascii', "$a"),
        b"prefix MSAA_SAFE_RANSOMWARE_MARKER suffix", "MSAA_Safe_Exact",
    ),
    YaraValidationCase(
        "YARA-SAFE-02", "Case-insensitive note marker", "Verify nocase handling for a benign simulated note.",
        _rule("MSAA_Safe_NoCase", '  $a = "msaa_safe_validation_note" ascii nocase', "$a"),
        b"MSAA_SAFE_VALIDATION_NOTE", "MSAA_Safe_NoCase",
    ),
    YaraValidationCase(
        "YARA-SAFE-03", "UTF-16 marker", "Verify wide-string matching without collecting document contents.",
        _rule("MSAA_Safe_Wide", '  $a = "MSAA_SAFE_WIDE_MARKER" wide', "$a"),
        "MSAA_SAFE_WIDE_MARKER".encode("utf-16le"), "MSAA_Safe_Wide",
    ),
    YaraValidationCase(
        "YARA-SAFE-04", "Hexadecimal sentinel", "Verify bounded hexadecimal-pattern matching.",
        _rule("MSAA_Safe_Hex", "  $a = { 4D 53 41 41 5F 53 41 46 45 }", "$a"),
        b"MSAA_SAFE", "MSAA_Safe_Hex",
    ),
    YaraValidationCase(
        "YARA-SAFE-05", "Two-of-three correlation", "Verify a rule needs multiple harmless ransomware-like markers.",
        _rule(
            "MSAA_Safe_TwoOfThree",
            '  $a = "MSAA_SAFE_RENAME"\n  $b = "MSAA_SAFE_ENTROPY"\n  $c = "MSAA_SAFE_NOTE"',
            "2 of ($a,$b,$c)",
        ),
        b"MSAA_SAFE_RENAME MSAA_SAFE_ENTROPY", "MSAA_Safe_TwoOfThree",
    ),
    YaraValidationCase(
        "YARA-SAFE-06", "All-signal cluster", "Verify a high-specificity multi-string condition.",
        _rule(
            "MSAA_Safe_AllSignals",
            '  $a = "MSAA_SAFE_CANARY"\n  $b = "MSAA_SAFE_BACKUP"\n  $c = "MSAA_SAFE_REWRITE"',
            "all of them",
        ),
        b"MSAA_SAFE_CANARY MSAA_SAFE_BACKUP MSAA_SAFE_REWRITE", "MSAA_Safe_AllSignals",
    ),
    YaraValidationCase(
        "YARA-SAFE-07", "Bounded regular expression", "Verify a constrained simulated incident identifier.",
        _rule("MSAA_Safe_Regex", "  $a = /MSAA_SAFE_NOTE_[0-9]{4}/ ascii", "$a"),
        b"MSAA_SAFE_NOTE_2026", "MSAA_Safe_Regex",
    ),
    YaraValidationCase(
        "YARA-SAFE-08", "Synthetic locked-extension content", "Verify an inert extension marker used only in fixtures.",
        _rule("MSAA_Safe_Extension", '  $a = ".msaa_locked_test" ascii', "$a"),
        b"document.msaa_locked_test", "MSAA_Safe_Extension",
    ),
    YaraValidationCase(
        "YARA-SAFE-09", "Benign shell fixture", "Verify script-format context plus an inert MSAA marker.",
        _rule(
            "MSAA_Safe_Shell",
            '  $header = "#!/bin/zsh"\n  $marker = "MSAA_SAFE_SHELL_FIXTURE"',
            "$header at 0 and $marker",
        ),
        b"#!/bin/zsh\necho MSAA_SAFE_SHELL_FIXTURE\n", "MSAA_Safe_Shell",
    ),
    YaraValidationCase(
        "YARA-SAFE-10", "Benign plist fixture", "Verify plist structure matching with a harmless /usr/bin/true action.",
        _rule(
            "MSAA_Safe_Plist",
            '  $plist = "<plist"\n  $args = "ProgramArguments"\n  $safe = "/usr/bin/true"',
            "all of them",
        ),
        b"<?xml version='1.0'?><plist><dict><key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>",
        "MSAA_Safe_Plist",
    ),
    YaraValidationCase(
        "YARA-SAFE-11", "Synthetic Mach-O context", "Verify format magic plus a non-production validation marker.",
        _rule(
            "MSAA_Safe_MachO",
            '  $marker = "MSAA_SAFE_MACHO_FIXTURE"',
            "uint32(0) == 0xfeedfacf and $marker",
        ),
        b"\xcf\xfa\xed\xfeMSAA_SAFE_MACHO_FIXTURE", "MSAA_Safe_MachO",
    ),
    YaraValidationCase(
        "YARA-SAFE-12", "File-size constrained marker", "Verify the rule respects a strict bounded fixture size.",
        _rule("MSAA_Safe_Size", '  $a = "MSAA_SAFE_SIZE_FIXTURE"', "$a and filesize < 4096"),
        b"MSAA_SAFE_SIZE_FIXTURE", "MSAA_Safe_Size",
    ),
)


NONMATCH_CASES: tuple[YaraValidationCase, ...] = (
    YaraValidationCase(
        "YARA-SAFE-13", "Near-miss negative control", "Ensure an almost-matching token does not alert.",
        _rule("MSAA_Safe_NearMiss", '  $a = "MSAA_SAFE_EXACT_TOKEN"', "$a"),
        b"MSAA_SAFE_EXACT_TOKE", None,
    ),
    YaraValidationCase(
        "YARA-SAFE-14", "Partial-cluster negative control", "Ensure one weak signal cannot satisfy a multi-signal rule.",
        _rule(
            "MSAA_Safe_PartialCluster",
            '  $a = "MSAA_SAFE_ONE"\n  $b = "MSAA_SAFE_TWO"\n  $c = "MSAA_SAFE_THREE"',
            "2 of them",
        ),
        b"MSAA_SAFE_ONE only", None,
    ),
    YaraValidationCase(
        "YARA-SAFE-15", "Ordinary document negative control", "Ensure normal text remains a clean control.",
        _rule("MSAA_Safe_BenignText", '  $a = "MSAA_SAFE_RANSOMWARE_ONLY"', "$a"),
        b"Quarterly project notes and ordinary document content.", None,
    ),
)


def _match_names(matches: object) -> list[str]:
    return sorted(str(getattr(item, "rule", item)) for item in list(matches))


def _run_match_case(backend: YaraBackend, case: YaraValidationCase) -> dict[str, object]:
    try:
        compiled = backend.compile({case.case_id.lower().replace("-", "_"): case.rule_source})
        names = _match_names(compiled.match(data=case.fixture, timeout=backend.timeout_seconds))
        passed = case.expected_rule in names if case.expected_rule else not names
        return {**case.metadata(), "result": "PASS" if passed else "FAIL", "passed": passed, "matches": names}
    except Exception as exc:  # noqa: BLE001 - backend failures are evidence, not suite crashes
        return {
            **case.metadata(), "result": "ERROR", "passed": False,
            "matches": [], "error_type": type(exc).__name__,
        }


def _gate_result(case_id: str, title: str, operation: Callable[[], object], expected_error: type[Exception] | None = None) -> dict[str, object]:
    try:
        operation()
        passed = expected_error is None
        return {"case_id": case_id, "title": title, "result": "PASS" if passed else "FAIL", "passed": passed}
    except Exception as exc:  # noqa: BLE001 - exact exception class is asserted below
        passed = expected_error is not None and isinstance(exc, expected_error)
        return {
            "case_id": case_id, "title": title, "result": "PASS" if passed else "FAIL",
            "passed": passed, "observed_error_type": type(exc).__name__,
        }


def run_yara_validation_suite(*, backend: YaraBackend | None = None) -> dict[str, object]:
    """Run 20 harmless in-memory YARA and rule-policy validation cases."""
    engine = backend or YaraBackend()
    results = [_run_match_case(engine, case) for case in (*MATCH_CASES, *NONMATCH_CASES)]
    malformed = "rule MSAA_Broken { strings: $a = \"x\" condition:"
    results.append(_gate_result(
        "YARA-SAFE-16", "Malformed rule compilation rejection",
        lambda: engine.compile({"malformed": malformed}), Exception,
    ))

    duplicate_a = _rule("MSAA_Duplicate_Name", '  $a = "MSAA_NAMESPACE_A"', "$a")
    duplicate_b = _rule("MSAA_Duplicate_Name", '  $b = "MSAA_NAMESPACE_B"', "$b")

    def namespace_gate() -> None:
        compiled = engine.compile({"namespace_a": duplicate_a, "namespace_b": duplicate_b})
        if _match_names(compiled.match(data=b"MSAA_NAMESPACE_A", timeout=engine.timeout_seconds)) != ["MSAA_Duplicate_Name"]:
            raise AssertionError("namespace-isolated rule did not match")

    results.append(_gate_result("YARA-SAFE-17", "Namespace collision isolation", namespace_gate))
    results.append(_gate_result(
        "YARA-SAFE-18", "Include directive policy rejection",
        lambda: validate_yara_source('include "outside.yar"\n' + duplicate_a), YaraRuleValidationError,
    ))
    results.append(_gate_result(
        "YARA-SAFE-19", "Unsupported module policy rejection",
        lambda: validate_yara_source('import "cuckoo"\n' + duplicate_a), YaraRuleValidationError,
    ))
    results.append(_gate_result(
        "YARA-SAFE-20", "Duplicate name policy rejection",
        lambda: validate_yara_source(duplicate_a + duplicate_b), YaraRuleValidationError,
    ))
    report: dict[str, object] = {
        "operation": "safe_ransomware_yara_validation_suite",
        "generated_at": utc_now_iso(),
        "suite_version": SUITE_VERSION,
        "backend_state": engine.capability.state,
        "case_count": len(results),
        "passed_count": sum(bool(item["passed"]) for item in results),
        "failed_count": sum(not bool(item["passed"]) for item in results),
        "all_passed": all(bool(item["passed"]) for item in results),
        "results": results,
        "safety": {
            "live_malware_used": False,
            "filesystem_writes": False,
            "commands_executed": False,
            "processes_spawned": False,
            "network_access": False,
            "user_files_touched": False,
        },
        "qualification": "These benign fixtures validate YARA compilation, matching, negative controls, namespaces, and policy gates. They do not prove that every ransomware family is detected.",
    }
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report


def validate_active_yara_release(
    *, database: ActiveMacOSMalwareDatabase | None = None, backend: YaraBackend | None = None,
) -> dict[str, object]:
    """Compile the active release and scan bounded benign sanity controls."""
    engine = backend or YaraBackend()
    try:
        snapshot = (database or ActiveMacOSMalwareDatabase()).load()
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "operation": "active_yara_release_validation", "status": "UNAVAILABLE",
            "release": "", "all_passed": False,
            "reason": f"Active release could not be read: {type(exc).__name__}.",
        }
    if not snapshot.version or not snapshot.yara_sources:
        return {
            "operation": "active_yara_release_validation", "status": "UNAVAILABLE",
            "release": snapshot.version, "all_passed": False,
            "reason": "No readable active YARA release is available.",
        }
    compiled = engine.compile(snapshot.yara_sources)
    controls = (
        b"MSAA harmless macOS definition validation fixture",
        b"#!/bin/zsh\necho harmless\n",
        b"<?xml version='1.0'?><plist><dict/></plist>",
        b"Ordinary user document negative control.",
    )
    unexpected = sorted({
        name
        for fixture in controls
        for name in _match_names(compiled.match(data=fixture, timeout=engine.timeout_seconds))
    })
    passed = not unexpected
    return {
        "operation": "active_yara_release_validation",
        "status": "PASS" if passed else "BENIGN_CONTROL_MATCH",
        "all_passed": passed,
        "release": snapshot.version,
        "manifest_sha256": snapshot.manifest_sha256,
        "loaded_rule_count": int(snapshot.counts.get("YARA_RULE", 0)),
        "compiled_namespace_count": len(snapshot.yara_sources),
        "benign_control_count": len(controls),
        "unexpected_matches": unexpected,
        "secret_or_file_content_exported": False,
    }


__all__ = [
    "MATCH_CASES", "NONMATCH_CASES", "SUITE_VERSION", "YaraValidationCase",
    "run_yara_validation_suite", "validate_active_yara_release",
]

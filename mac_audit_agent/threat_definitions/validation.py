"""Definition gates: schema, action policy, deltas, YARA, and conflicts."""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Iterable
from dataclasses import replace

from .models import (
    DefinitionAction,
    DefinitionLifecycle,
    DefinitionType,
    Severity,
    SourcePolicy,
    ThreatDefinition,
    TrustClass,
    ValidationIssue,
    ValidationResult,
    ValidationState,
    utc_now,
)
from .normalization import NormalizationError, definition_id, normalize_value

_ACTION_RANK = {
    DefinitionAction.DISABLED: 0, DefinitionAction.OBSERVE: 1, DefinitionAction.LOG: 2,
    DefinitionAction.CORRELATE: 3, DefinitionAction.ALERT: 4,
    DefinitionAction.QUARANTINE_CANDIDATE: 5, DefinitionAction.BLOCK: 6,
}

_YARA_RULE_START = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b[^\{]*\{")
_YARA_IMPORT = re.compile(r'(?m)^\s*import\s+"[A-Za-z0-9_]+"\s*$')


def split_yara_rules(source: str) -> list[tuple[str, str]]:
    """Extract bounded top-level rules for failure isolation; never interprets rule content."""
    prefix = "\n".join(_YARA_IMPORT.findall(source))
    output: list[tuple[str, str]] = []
    cursor = 0
    while True:
        match = _YARA_RULE_START.search(source, cursor)
        if match is None:
            break
        depth = 1
        index = match.end()
        quote = ""
        escaped = False
        line_comment = False
        block_comment = False
        while index < len(source) and depth:
            character = source[index]
            following = source[index + 1] if index + 1 < len(source) else ""
            if line_comment:
                line_comment = character != "\n"
            elif block_comment:
                if character == "*" and following == "/":
                    block_comment = False
                    index += 1
            elif quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif character == "/" and following == "/":
                line_comment = True
                index += 1
            elif character == "/" and following == "*":
                block_comment = True
                index += 1
            elif character in {'"', "'"}:
                quote = character
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            index += 1
        if depth:
            break
        block = source[match.start():index].strip()
        output.append((match.group(1), f"{prefix}\n{block}".strip() + "\n"))
        cursor = index
    return output


class DefinitionValidator:
    def __init__(self, *, maximum_definitions: int = 2_000_000, maximum_yara_bytes: int = 64 * 1024 * 1024, maximum_single_yara_rule_bytes: int = 4 * 1024 * 1024, maximum_yara_compile_seconds: float = 30.0, maximum_yara_scan_seconds: float = 5.0) -> None:
        self.maximum_definitions = maximum_definitions
        self.maximum_yara_bytes = maximum_yara_bytes
        self.maximum_single_yara_rule_bytes = maximum_single_yara_rule_bytes
        self.maximum_yara_compile_seconds = maximum_yara_compile_seconds
        self.maximum_yara_scan_seconds = maximum_yara_scan_seconds

    def validate(self, definitions: Iterable[ThreatDefinition], *, run_yara_gate: bool = True) -> ValidationResult:
        items = list(definitions)
        issues: list[ValidationIssue] = []
        if len(items) > self.maximum_definitions:
            return ValidationResult(False, ValidationState.REJECTED, (ValidationIssue("DEFINITION_LIMIT", "Definition count exceeds the configured bound.", Severity.CRITICAL),), rejected_count=len(items))
        seen: set[str] = set()
        for item in items:
            try:
                canonical = normalize_value(item.definition_type, item.value)
            except (NormalizationError, ValueError) as exc:
                issues.append(ValidationIssue("INVALID_VALUE", str(exc), Severity.HIGH, item.definition_id))
                continue
            if canonical != item.value or definition_id(item.definition_type, canonical) != item.definition_id:
                issues.append(ValidationIssue("NONCANONICAL_DEFINITION", "Definition value or identifier is not canonical.", Severity.HIGH, item.definition_id))
            if item.canonical_key in seen:
                issues.append(ValidationIssue("DUPLICATE_DEFINITION", "Duplicate canonical indicator remains after normalization.", Severity.MEDIUM, item.definition_id))
            seen.add(item.canonical_key)
            if not math.isfinite(item.confidence) or not 0 <= item.confidence <= 1:
                issues.append(ValidationIssue("INVALID_CONFIDENCE", "Confidence must be between 0 and 1.", Severity.HIGH, item.definition_id))
            if not item.provenance:
                issues.append(ValidationIssue("MISSING_PROVENANCE", "Definition has no source provenance.", Severity.HIGH, item.definition_id))
            if item.expires_at and item.expires_at <= utc_now() and item.lifecycle not in {DefinitionLifecycle.EXPIRED, DefinitionLifecycle.REVOKED, DefinitionLifecycle.DISABLED}:
                issues.append(ValidationIssue("EXPIRED_ACTIVE_DEFINITION", "Expired definition is not marked expired or disabled.", Severity.MEDIUM, item.definition_id))
            if item.definition_type in {DefinitionType.BEHAVIOR_RULE, DefinitionType.DETECTION_RULE}:
                try:
                    rule = json.loads(item.value)
                    required = {"rule_id", "version", "description", "severity", "confidence", "required_telemetry", "conditions", "recommended_response"}
                    if not isinstance(rule, dict) or not required.issubset(rule) or not isinstance(rule.get("conditions"), dict) or not isinstance(rule.get("required_telemetry"), list):
                        raise ValueError
                except (json.JSONDecodeError, TypeError, ValueError):
                    issues.append(ValidationIssue("BEHAVIOR_RULE_SCHEMA_INVALID", "Behavior/detection rule is missing required versioned fields.", Severity.HIGH, item.definition_id))
        if run_yara_gate:
            for item in items:
                if item.definition_type == DefinitionType.YARA_RULE:
                    issue = self._validate_yara(item)
                    if issue:
                        issues.append(issue)
        rejected = {item.definition_id for item in issues if item.definition_id and item.severity in {Severity.HIGH, Severity.CRITICAL}}
        fatal = any(issue.severity in {Severity.HIGH, Severity.CRITICAL} for issue in issues)
        return ValidationResult(not fatal, ValidationState.VALID if not fatal else ValidationState.REJECTED, tuple(issues), len(items) - len(rejected), len(rejected))

    def _validate_yara(self, definition: ThreatDefinition) -> ValidationIssue | None:
        encoded = definition.value.encode("utf-8")
        if not encoded or len(encoded) > self.maximum_yara_bytes or b"\x00" in encoded:
            return ValidationIssue("YARA_SIZE_INVALID", "YARA package is empty, contains NUL, or exceeds its bound.", Severity.HIGH, definition.definition_id)
        extracted = split_yara_rules(definition.value)
        if any(len(source.encode("utf-8")) > self.maximum_single_yara_rule_bytes for _name, source in extracted):
            return ValidationIssue("YARA_RULE_SIZE_INVALID", "An individual YARA rule exceeds the configured bound.", Severity.HIGH, definition.definition_id)
        started = time.monotonic()
        try:
            import yara

            compiled = yara.compile(source=definition.value)
            compile_seconds = time.monotonic() - started
            if compile_seconds > self.maximum_yara_compile_seconds:
                return ValidationIssue("YARA_PERFORMANCE_GATE", "YARA compilation exceeded the configured time budget.", Severity.HIGH, definition.definition_id)
            fixtures = (
                b"MSAA harmless macOS definition validation fixture",
                b"#!/bin/zsh\necho harmless\n",
                b"<?xml version='1.0'?><plist><dict/></plist>",
            )
            for fixture in fixtures:
                scan_started = time.monotonic()
                matches = compiled.match(data=fixture, timeout=max(1, int(self.maximum_yara_scan_seconds)))
                if time.monotonic() - scan_started > self.maximum_yara_scan_seconds:
                    return ValidationIssue("YARA_PERFORMANCE_GATE", "YARA benign-fixture scan exceeded the time budget.", Severity.HIGH, definition.definition_id)
                if matches:
                    return ValidationIssue("YARA_BENIGN_FIXTURE_MATCH", "YARA package matched an MSAA benign sanity fixture.", Severity.HIGH, definition.definition_id)
        except ImportError:
            return ValidationIssue("YARA_DEPENDENCY_MISSING", "YARA compilation dependency is unavailable; package cannot be activated.", Severity.HIGH, definition.definition_id)
        except Exception as exc:  # noqa: BLE001 - YARA exposes backend-specific compile exceptions
            return ValidationIssue("YARA_COMPILATION_FAILED", f"YARA compilation failed: {type(exc).__name__}", Severity.HIGH, definition.definition_id)
        return None

    @staticmethod
    def validate_delta(previous_count: int, new_count: int, policy: SourcePolicy) -> ValidationResult:
        issues: list[ValidationIssue] = []
        if new_count < policy.expected_minimum_count:
            issues.append(ValidationIssue("EMPTY_OR_UNDERSIZED_FEED", "Feed count is below the provider-specific minimum; active definitions remain untouched.", Severity.CRITICAL))
        if previous_count > 0:
            reduction = 1 - (new_count / previous_count)
            growth = new_count / previous_count
            if reduction > policy.maximum_reduction_fraction:
                issues.append(ValidationIssue("SUSPICIOUS_FEED_REDUCTION", f"Feed shrank by {reduction:.1%}; manual review is required.", Severity.CRITICAL))
            if growth > policy.maximum_growth_factor:
                issues.append(ValidationIssue("SUSPICIOUS_FEED_GROWTH", f"Feed grew by {growth:.1f}x; manual review is required.", Severity.HIGH))
        return ValidationResult(not issues, ValidationState.VALID if not issues else ValidationState.REJECTED, tuple(issues), new_count if not issues else 0, new_count if issues else 0)


def apply_prevention_policy(definition: ThreatDefinition, *, approved_for_blocking: bool = False) -> ThreatDefinition:
    """Keep intelligence separate from prevention; external BLOCK needs explicit approval."""
    external = any(item.trust_class not in {TrustClass.LOCAL_ADMIN, TrustClass.AUTHORITATIVE} for item in definition.provenance)
    if definition.action == DefinitionAction.BLOCK and (external or not approved_for_blocking):
        return replace(definition, action=DefinitionAction.ALERT, metadata={**definition.metadata, "requested_action": "BLOCK", "prevention_policy": "BLOCK_REQUIRES_EXPLICIT_APPROVAL"})
    return definition


def deduplicate(definitions: Iterable[ThreatDefinition]) -> tuple[list[ThreatDefinition], list[dict[str, str]]]:
    merged: dict[str, ThreatDefinition] = {}
    conflicts: list[dict[str, str]] = []
    for incoming in definitions:
        key = incoming.canonical_key
        existing = merged.get(key)
        if existing is None:
            merged[key] = apply_prevention_policy(incoming)
            continue
        provenance = {f"{item.source_id}\0{item.source_reference or ''}": item for item in (*existing.provenance, *incoming.provenance)}
        by_group: dict[str, float] = {}
        for item in provenance.values():
            group = item.dependency_group or item.source_id
            by_group[group] = max(by_group.get(group, 0.0), item.source_confidence * max(existing.confidence, incoming.confidence))
        effective = 1.0
        for confidence in by_group.values():
            effective *= 1 - max(0.0, min(confidence, 1.0))
        effective = 1 - effective
        action = max((existing.action, apply_prevention_policy(incoming).action), key=lambda item: _ACTION_RANK[item])
        merged[key] = replace(
            existing, confidence=round(effective, 6), action=action,
            provenance=tuple(sorted(provenance.values(), key=lambda item: (item.source_id, item.source_reference or ""))),
            tags=tuple(sorted({*existing.tags, *incoming.tags})),
            first_seen=min(filter(None, (existing.first_seen, incoming.first_seen)), default=None),
            last_seen=max(filter(None, (existing.last_seen, incoming.last_seen)), default=None),
        )
    allow_values = {item.value for item in merged.values() if item.definition_type == DefinitionType.ALLOWLIST}
    for item in merged.values():
        if item.definition_type in {DefinitionType.DENYLIST, DefinitionType.DOMAIN, DefinitionType.HOSTNAME, DefinitionType.IPV4, DefinitionType.IPV6, DefinitionType.URL} and item.value in allow_values:
            conflicts.append({"code": "ALLOWLIST_POLICY_CONFLICT", "value": item.value, "definition_id": item.definition_id})
    return sorted(merged.values(), key=lambda item: item.canonical_key), conflicts


__all__ = ["DefinitionValidator", "apply_prevention_policy", "deduplicate", "split_yara_rules"]

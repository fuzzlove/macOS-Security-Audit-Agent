"""Offline, deterministic validation helpers; fixture text is never executed."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .shell_config import ShellGuardConfig
from .shell_scanner import scan_request


@dataclass
class CorrelationSession:
    """Correlates scanner-only submissions while retaining no raw commands."""

    session_id: str
    window_seconds: float = 60.0
    records: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def _path_tokens(text: str) -> tuple[str, ...]:
        paths = re.findall(r"(?:/tmp/|\$HOME/Library/)[A-Za-z0-9_./${}-]+", text)
        return tuple(sorted({hashlib.sha256(item.encode()).hexdigest() for item in paths}))

    def observe(self, command: str, observed_at: float) -> dict[str, Any]:
        result = scan_request({"command": command, "phase": "test", "paste_origin": True}, ShellGuardConfig())
        record = {
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "rule_ids": list(result.rule_ids),
            "path_tokens": self._path_tokens(command),
            "observed_at": observed_at,
            "session_id": self.session_id,
        }
        self.records.append(record)
        self.records = [item for item in self.records if observed_at - float(item["observed_at"]) <= self.window_seconds]
        rules = {rule for item in self.records for rule in item["rule_ids"]}
        text_flags = [
            ("retrieve", bool(re.search(r"\b(?:curl|wget)\b", command))),
            ("permission", bool(re.search(r"\bchmod\b", command))),
            ("execute", bool(re.search(r"(?:^|[;&\n])\s*(?:/tmp/|(?:ba|z)?sh\s+/tmp/)", command))),
            ("decode", bool(re.search(r"\b(?:base64|openssl|xxd|gzip|gunzip)\b", command))),
            ("persistence", bool(re.search(r"LaunchAgents|launchctl\s+bootstrap", command))),
            ("quarantine", "com.apple.quarantine" in command),
            ("dynamic", bool(re.search(r"\beval\b|(?:ba|z)?sh\s+", command))),
        ]
        record["flags"] = [name for name, matched in text_flags if matched]
        all_flags = {flag for item in self.records for flag in item.get("flags", [])}
        shared_path = any(set(a["path_tokens"]) & set(b["path_tokens"]) for i,a in enumerate(self.records) for b in self.records[i+1:])
        correlated: list[str] = []
        if shared_path and {"retrieve","permission","execute"} <= all_flags: correlated += ["correlated_download_stage_execute","same_path_correlation"]
        if shared_path and {"decode","execute"} <= all_flags: correlated += ["correlated_decode_execute"]
        if {"retrieve","persistence"} <= all_flags: correlated += ["correlated_downloaded_persistence"]
        if shared_path and {"retrieve","quarantine","execute"} <= all_flags: correlated += ["correlated_security_bypass_execution"]
        if {"retrieve","decode","dynamic"} <= all_flags: correlated += ["correlated_network_decode_execute"]
        return {"decision":"block" if correlated else result.decision,"rule_ids":sorted(rules|set(correlated)),"retained":record}


def evaluate_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate inert text or declared simulated telemetry without side effects."""
    if fixture.get("simulation"):
        rules = set(fixture.get("simulated_rule_ids", []))
        return {"decision": fixture.get("simulated_decision", "warn"), "score": int(fixture.get("minimum_score", 4)), "rule_ids": sorted(rules), "decoder_depth": 0, "processing_time_ms": 0.0, "coverage_type": "simulated_endpoint_context"}
    result = scan_request({"command":fixture["command_text"],"phase":"test","paste_origin":fixture["paste_origin"],"multiline":fixture["multiline"],"trailing_newline":fixture["trailing_newline"]},ShellGuardConfig())
    payload=result.to_dict();payload["coverage_type"]="pre_execution_scanner";return payload


__all__ = ["CorrelationSession", "evaluate_fixture"]

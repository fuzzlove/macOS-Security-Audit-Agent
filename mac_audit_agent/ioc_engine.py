from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.storage import json_safe


IOC_TYPES = {"sha256", "sha1", "md5", "domain", "ip", "filename", "path_fragment", "process_name"}
HASH_LENGTH_TYPES = {64: "sha256", 40: "sha1", 32: "md5"}
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


@dataclass(frozen=True)
class IOCIndicator:
    indicator: str
    indicator_type: str
    source: str = "imported"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IOCMatchFinding:
    indicator: str
    indicator_type: str
    matched_value: str
    source: str
    confidence: str
    recommended_action: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = json_safe(payload["evidence"])
        return payload


@dataclass
class IOCMatchReport:
    generated_at: str
    local_only: bool
    upload_performed: bool
    blocking_performed: bool
    indicators_loaded: int
    matches: list[IOCMatchFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "local_only": self.local_only,
            "upload_performed": self.upload_performed,
            "blocking_performed": self.blocking_performed,
            "indicators_loaded": self.indicators_loaded,
            "match_count": len(self.matches),
            "matches": [match.to_dict() for match in self.matches],
            "warnings": list(self.warnings),
        }


def infer_indicator_type(value: str) -> str:
    normalized = value.strip().strip('"').strip("'")
    lowered = normalized.lower()
    compact_hash = lowered.replace(":", "").replace("-", "")
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", compact_hash):
        return HASH_LENGTH_TYPES[len(compact_hash)]
    if IP_RE.fullmatch(normalized):
        return "ip"
    if "/" in normalized or normalized.startswith(".") or normalized.startswith("~"):
        return "path_fragment"
    if DOMAIN_RE.fullmatch(lowered):
        return "domain"
    if "." in Path(normalized).name and "/" not in normalized:
        return "filename"
    return "process_name"


def normalize_indicator(value: str, indicator_type: str | None = None) -> IOCIndicator | None:
    cleaned = str(value or "").strip().strip('"').strip("'")
    if not cleaned or cleaned.startswith("#"):
        return None
    kind = (indicator_type or infer_indicator_type(cleaned)).strip().lower()
    aliases = {"hash_sha256": "sha256", "hash_sha1": "sha1", "hash_md5": "md5", "process": "process_name", "path": "path_fragment"}
    kind = aliases.get(kind, kind)
    if kind not in IOC_TYPES:
        kind = infer_indicator_type(cleaned)
    if kind in {"sha256", "sha1", "md5", "domain", "filename", "process_name"}:
        cleaned = cleaned.lower()
    return IOCIndicator(indicator=cleaned, indicator_type=kind)


def parse_ioc_text(text: str, *, source: str = "text") -> list[IOCIndicator]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        return parse_ioc_json(stripped, source=source)
    if "," in stripped.splitlines()[0]:
        try:
            return parse_ioc_csv(stripped, source=source)
        except csv.Error:
            pass
    indicators: list[IOCIndicator] = []
    for line in stripped.splitlines():
        candidate = line.split("#", 1)[0].strip()
        if not candidate:
            continue
        for token in re.split(r"[\s,]+", candidate):
            indicator = normalize_indicator(token)
            if indicator is not None:
                indicators.append(IOCIndicator(indicator.indicator, indicator.indicator_type, source=source))
    return _dedupe(indicators)


def parse_ioc_csv(text: str, *, source: str = "csv") -> list[IOCIndicator]:
    rows = list(csv.DictReader(io.StringIO(text)))
    indicators: list[IOCIndicator] = []
    if rows:
        for row in rows:
            value = row.get("indicator") or row.get("value") or row.get("ioc") or row.get("hash") or row.get("ip") or row.get("domain") or row.get("filename") or row.get("path") or row.get("process_name") or ""
            kind = row.get("type") or row.get("indicator_type") or ""
            indicator = normalize_indicator(value, kind or None)
            if indicator is not None:
                indicators.append(IOCIndicator(indicator.indicator, indicator.indicator_type, source=source, description=str(row.get("description", ""))))
        return _dedupe(indicators)
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        indicator = normalize_indicator(row[0], row[1] if len(row) > 1 else None)
        if indicator is not None:
            indicators.append(IOCIndicator(indicator.indicator, indicator.indicator_type, source=source))
    return _dedupe(indicators)


def parse_ioc_json(text: str, *, source: str = "json") -> list[IOCIndicator]:
    payload = json.loads(text)
    values = payload.get("indicators", payload.get("iocs", [])) if isinstance(payload, dict) else payload
    if isinstance(values, dict):
        values = [{"indicator": value, "type": key} for key, group in values.items() for value in (group if isinstance(group, list) else [group])]
    indicators: list[IOCIndicator] = []
    for item in values if isinstance(values, list) else []:
        if isinstance(item, str):
            indicator = normalize_indicator(item)
        elif isinstance(item, dict):
            indicator = normalize_indicator(str(item.get("indicator") or item.get("value") or item.get("ioc") or ""), str(item.get("type") or item.get("indicator_type") or "") or None)
            if indicator is not None:
                indicator = IOCIndicator(indicator.indicator, indicator.indicator_type, source=source, description=str(item.get("description", "")))
        else:
            indicator = None
        if indicator is not None:
            indicators.append(indicator)
    return _dedupe(indicators)


def load_ioc_file(path: Path) -> list[IOCIndicator]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_ioc_json(text, source=str(path))
    if suffix == ".csv":
        return parse_ioc_csv(text, source=str(path))
    return parse_ioc_text(text, source=str(path))


def export_matches_json(report: IOCMatchReport | dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict() if hasattr(report, "to_dict") else report
    output_path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True), encoding="utf-8")
    return output_path


class OfflineIOCEngine:
    def match(self, indicators: list[IOCIndicator | dict[str, Any] | str], artifacts: dict[str, Any]) -> IOCMatchReport:
        normalized = self._normalize_indicators(indicators)
        observations = self._observations(artifacts)
        matches: list[IOCMatchFinding] = []
        seen: set[tuple[str, str, str, str]] = set()
        for indicator in normalized:
            for observation in observations:
                if self._matches(indicator, observation):
                    key = (indicator.indicator, indicator.indicator_type, observation["matched_value"], observation["source"])
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(
                        IOCMatchFinding(
                            indicator=indicator.indicator,
                            indicator_type=indicator.indicator_type,
                            matched_value=observation["matched_value"],
                            source=observation["source"],
                            confidence="high" if indicator.indicator_type in {"sha256", "sha1", "md5", "ip", "domain"} else "medium",
                            recommended_action="Review locally, preserve evidence, and verify whether the indicator is expected. No upload, blocking, or destructive remediation was performed.",
                            evidence=observation["evidence"],
                        )
                    )
        return IOCMatchReport(
            generated_at=utc_now_iso(),
            local_only=True,
            upload_performed=False,
            blocking_performed=False,
            indicators_loaded=len(normalized),
            matches=matches,
            warnings=[
                "Offline IOC matching is local-only.",
                "MSAA does not upload indicators or artifacts.",
                "MSAA does not automatically block, quarantine, delete, or remediate IOC matches.",
            ],
        )

    def _normalize_indicators(self, indicators: list[IOCIndicator | dict[str, Any] | str]) -> list[IOCIndicator]:
        normalized: list[IOCIndicator] = []
        for item in indicators:
            if isinstance(item, IOCIndicator):
                normalized.append(item)
            elif isinstance(item, str):
                indicator = normalize_indicator(item)
                if indicator is not None:
                    normalized.append(indicator)
            elif isinstance(item, dict):
                indicator = normalize_indicator(str(item.get("indicator") or item.get("value") or ""), str(item.get("indicator_type") or item.get("type") or "") or None)
                if indicator is not None:
                    normalized.append(indicator)
        return _dedupe(normalized)

    def _observations(self, artifacts: dict[str, Any]) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        for item in self._list((artifacts.get("processes", {}) or {}).get("all", []) if isinstance(artifacts.get("processes", {}), dict) else []):
            payload = self._as_dict(item)
            path = str(payload.get("command_path", ""))
            process_name = str(payload.get("process_name") or Path(path).name)
            self._add_path_observations(observations, path, "process", payload)
            if process_name:
                observations.append({"type": "process_name", "matched_value": process_name.lower(), "source": "process", "evidence": payload})
            for hash_type in ("sha256", "sha1", "md5"):
                if payload.get(hash_type):
                    observations.append({"type": hash_type, "matched_value": str(payload.get(hash_type)).lower(), "source": "process", "evidence": payload})
        for item in self._list(artifacts.get("file_issues", [])):
            payload = self._as_dict(item)
            path = str(payload.get("path", ""))
            self._add_path_observations(observations, path, "file_inventory", payload)
            for hash_type in ("sha256", "sha1", "md5"):
                if payload.get(hash_type):
                    observations.append({"type": hash_type, "matched_value": str(payload.get(hash_type)).lower(), "source": "file_inventory", "evidence": payload})
        ports = artifacts.get("ports", {}) if isinstance(artifacts.get("ports", {}), dict) else {}
        for item in [*self._list(ports.get("active_connections", [])), *self._list(ports.get("listening", []))]:
            payload = self._as_dict(item)
            for field in ("remote_address", "local_address"):
                endpoint = str(payload.get(field, ""))
                if endpoint:
                    host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
                    observations.append({"type": "ip", "matched_value": host, "source": "network_connection", "evidence": payload})
                    observations.append({"type": "domain", "matched_value": host.lower(), "source": "network_connection", "evidence": payload})
        for item in self._list(artifacts.get("launch_snapshots", [])):
            payload = self._as_dict(item)
            self._add_path_observations(observations, str(payload.get("program", "")), "persistence_target", payload)
            self._add_path_observations(observations, str(payload.get("path", "")), "persistence_entry", payload)
        for item in self._list(artifacts.get("reports", [])):
            payload = self._as_dict(item)
            text = json.dumps(json_safe(payload), sort_keys=True).lower()
            observations.append({"type": "report_text", "matched_value": text, "source": "report", "evidence": payload})
        return observations

    def _add_path_observations(self, observations: list[dict[str, Any]], path: str, source: str, payload: dict[str, Any]) -> None:
        if not path:
            return
        observations.append({"type": "path_fragment", "matched_value": path.lower(), "source": source, "evidence": payload})
        observations.append({"type": "filename", "matched_value": Path(path).name.lower(), "source": source, "evidence": payload})

    def _matches(self, indicator: IOCIndicator, observation: dict[str, Any]) -> bool:
        value = observation["matched_value"]
        if indicator.indicator_type == observation["type"]:
            if indicator.indicator_type in {"path_fragment", "filename", "process_name"}:
                return indicator.indicator in value
            return indicator.indicator == value
        if observation["type"] == "report_text":
            return indicator.indicator.lower() in value
        return False

    def _list(self, value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def _as_dict(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return dict(value.__dict__)
        return {"value": json_safe(value)}


def _dedupe(indicators: list[IOCIndicator]) -> list[IOCIndicator]:
    seen: set[tuple[str, str]] = set()
    result: list[IOCIndicator] = []
    for indicator in indicators:
        key = (indicator.indicator, indicator.indicator_type)
        if key not in seen:
            seen.add(key)
            result.append(indicator)
    return result

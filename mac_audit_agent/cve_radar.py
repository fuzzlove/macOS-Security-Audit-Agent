from __future__ import annotations

import hashlib
import json
import logging
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import ScanResult, utc_now_iso
from mac_audit_agent.storage import AuditDatabase, json_safe
from mac_audit_agent.vulnerability_review import (
    APPLE_SECURITY_RELEASES_URL,
    CISA_KEV_URL,
    FIRST_EPSS_API_URL,
    NVD_CVE_API_URL,
    VulnerabilityCatalogUpdater,
    compare_versions,
    extract_version,
    default_local_inventory,
    normalize_product_name,
    version_matches_affected_range,
)


UPDATE_INTERVAL_SECONDS = 6 * 60 * 60
APPLE_PRODUCTS = {"macos", "safari", "webkit", "xcode", "commandlinetools", "commandlinetool"}
SURFACE_SEVERITIES = {"critical", "high"}
LOGGER = logging.getLogger(__name__)


def _is_simulated_forecast_payload(payload: dict[str, Any]) -> bool:
    nested_payload = payload.get("payload_json", {}) if isinstance(payload.get("payload_json", {}), dict) else {}
    return bool(
        payload.get("simulated")
        or str(payload.get("source_mode", "")).startswith("demo")
        or nested_payload.get("simulated")
        or str(nested_payload.get("source_mode", "")).startswith("demo")
    )


def _run_command(command: list[str], timeout: int = 5) -> str:
    executable = command[0] if Path(command[0]).exists() else shutil.which(command[0])
    if not executable:
        return ""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or completed.stderr or "").strip()


def _run_command_result(command: list[str], timeout: int = 5) -> tuple[str, bool]:
    executable = command[0] if Path(command[0]).exists() else shutil.which(command[0])
    if not executable:
        return "", False
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "", False
    output = (completed.stdout or completed.stderr or "").strip()
    return output, completed.returncode == 0


def _parse_version(text: str) -> str:
    match = re.search(r"(\d+(?:\.\d+){0,4})", text)
    return match.group(1) if match else ""


def _utc_to_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hash_alert_id(cve_id: str) -> str:
    return hashlib.sha256(cve_id.encode("utf-8")).hexdigest()[:16]


def _card_payload(card: Any) -> dict[str, Any]:
    if hasattr(card, "to_dict"):
        try:
            payload = card.to_dict()
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            return payload
    if isinstance(card, dict):
        return dict(card)
    return json_safe(getattr(card, "__dict__", {})) if hasattr(card, "__dict__") else {}


def _severity_from_cvss(cvss_score: float | None) -> str:
    score = float(cvss_score or 0.0)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _family_aliases(product: str) -> set[str]:
    normalized = normalize_product_name(product)
    aliases = {normalized}
    if normalized in {"macos", "osx"}:
        aliases.update({"apple", "safari", "webkit", "xcode", "commandlinetools"})
    if normalized in {"safari", "webkit"}:
        aliases.update({"apple", "macos"})
    if normalized in {"xcode", "commandlinetools"}:
        aliases.update({"apple", "macos"})
    if normalized in {"git"}:
        aliases.add("git")
    if normalized in {"python", "python3", "pip"}:
        aliases.update({"python", "cpython", "pip"})
    if normalized in {"node", "npm", "nodejs"}:
        aliases.update({"node", "npm", "nodejs"})
    if normalized in {"openssl", "libressl"}:
        aliases.update({"openssl", "libressl"})
    if normalized in {"curl", "wget", "java"}:
        aliases.add(normalized)
    if normalized in {"docker", "colima", "orbstack"}:
        aliases.update({"docker", "container", "vm"})
    if normalized in {"chrome", "chromium", "firefox", "edge", "brave", "opera"}:
        aliases.update({"browser", "web"})
    return aliases


def _command_display(command: list[str]) -> str:
    return " ".join(command)


def collect_local_inventory() -> dict[str, Any]:
    inventory: dict[str, Any] = {
        "collected_at": utc_now_iso(),
        "platform": platform.platform(),
        "macos": platform.mac_ver()[0],
        "products": [],
        "summary": {},
    }
    products: list[dict[str, Any]] = []

    def add_product(
        product: str,
        version: str,
        *,
        source: str,
        vendor: str = "",
        family: str = "",
        path: str = "",
        notes: str = "",
    ) -> None:
        if not product:
            return
        products.append(
            {
                "product": product,
                "normalized_product": normalize_product_name(product),
                "version": version,
                "source": source,
                "vendor": vendor,
                "family": family or normalize_product_name(product),
                "path": path,
                "notes": notes,
            }
        )

    base_inventory = default_local_inventory()
    for key, item in base_inventory.items():
        product = str(item.get("product", key) or key)
        version = str(item.get("version", "") or "")
        add_product(product, version, source=f"command:{key}")

    brew_list = _run_command(["brew", "list", "--versions"], timeout=10)
    if brew_list:
        for line in brew_list.splitlines():
            parts = line.split()
            if not parts:
                continue
            add_product(parts[0], parts[1] if len(parts) > 1 else "", source="brew", vendor="homebrew", family="homebrew")

    pip_list = _run_command(["python3", "-m", "pip", "list", "--format=json"], timeout=12)
    if pip_list:
        try:
            for item in json.loads(pip_list):
                name = str(item.get("name", "")).strip()
                version = str(item.get("version", "")).strip()
                if name:
                    add_product(name, version, source="pip", vendor="python", family="python")
        except json.JSONDecodeError:
            pass

    npm_global = _run_command(["npm", "ls", "-g", "--depth=0", "--json"], timeout=12)
    if npm_global:
        try:
            payload = json.loads(npm_global)
            for name, item in (payload.get("dependencies") or {}).items():
                if not isinstance(item, dict):
                    continue
                add_product(str(name), str(item.get("version", "")), source="npm", vendor="node", family="node")
        except json.JSONDecodeError:
            pass

    browser_commands = {
        "Safari": ["/Applications/Safari.app/Contents/MacOS/Safari", "--version"],
        "Chrome": ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--version"],
        "Chromium": ["/Applications/Chromium.app/Contents/MacOS/Chromium", "--version"],
        "Firefox": ["/Applications/Firefox.app/Contents/MacOS/firefox", "--version"],
        "Microsoft Edge": ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "--version"],
        "Brave Browser": ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser", "--version"],
        "Opera": ["/Applications/Opera.app/Contents/MacOS/Opera", "--version"],
    }
    for product, command in browser_commands.items():
        text = _run_command(command, timeout=5)
        if text:
            add_product(product, _parse_version(text) or text[:80], source=f"browser:{product}", family="browser")

    security_tools = {
        "nmap": ["nmap", "--version"],
        "wireshark": ["wireshark", "--version"],
        "burpsuite": ["burpsuite", "--version"],
        "mitmproxy": ["mitmproxy", "--version"],
        "sqlmap": ["sqlmap", "--version"],
        "gpg": ["gpg", "--version"],
        "nuclei": ["nuclei", "-version"],
    }
    for product, command in security_tools.items():
        text = _run_command(command, timeout=5)
        if text:
            add_product(product, _parse_version(text) or text[:80], source=f"security:{product}", family="security")

    inventory["products"] = products
    inventory["summary"] = {
        "product_count": len(products),
        "command_inventory_count": len(base_inventory),
        "homebrew_count": sum(1 for item in products if item.get("source") == "brew"),
        "pip_count": sum(1 for item in products if item.get("source") == "pip"),
        "npm_count": sum(1 for item in products if item.get("source") == "npm"),
        "browser_count": sum(1 for item in products if str(item.get("family", "")) == "browser"),
        "security_tool_count": sum(1 for item in products if str(item.get("family", "")) == "security"),
    }
    return inventory


def group_alerts_for_display(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: list[dict[str, Any]] = []
    apple_alerts = [item for item in alerts if item.get("apple_related")]
    non_apple_alerts = [item for item in alerts if not item.get("apple_related")]
    if apple_alerts:
        apple_sorted = sorted(apple_alerts, key=lambda item: (item.get("kev", False), item.get("severity", "info")), reverse=True)
        grouped.append(
            {
                "card_id": "apple-security-update",
                "title": "Apple Security Update Available",
                "severity": max((item.get("severity", "high") for item in apple_alerts), key=lambda value: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(value, 0), default="high"),
                "kev": any(item.get("kev", False) for item in apple_alerts),
                "epss_percentile": max(float(item.get("epss_percentile") or 0.0) for item in apple_alerts),
                "applicability_confidence": "high" if any(item.get("applicability_confidence") == "high" for item in apple_alerts) else "medium",
                "why_shown_to_you": "Apple-related CVEs match your detected macOS or browser family.",
                "recommended_action": "Open System Settings > General > Software Update and review Apple's release notes for the matching security update.",
                "update_guidance": "Install the Apple security update that matches your macOS, Safari, WebKit, or Xcode build if supported by your environment.",
                "source": "apple",
                "apple_related": True,
                "status": "new" if any(item.get("status") == "new" for item in apple_alerts) else apple_alerts[0].get("status", "new"),
                "first_seen": min((item.get("first_seen", "") for item in apple_alerts if item.get("first_seen")), default=""),
                "last_seen": max((item.get("last_seen", "") for item in apple_alerts if item.get("last_seen")), default=""),
                "cve_ids": [item.get("cve_id", "") for item in apple_alerts if item.get("cve_id")],
                "alerts": apple_sorted,
                "local_match_evidence": [evidence for item in apple_alerts for evidence in item.get("local_match_evidence", [])],
                "references": sorted({ref for item in apple_alerts for ref in item.get("references", []) if ref}),
                "should_surface": any(item.get("should_surface", False) for item in apple_alerts),
            }
        )
    grouped.extend(non_apple_alerts)
    return grouped


@dataclass
class CveRadarAlert:
    alert_id: str
    cve_id: str
    title: str
    published_date: str
    last_modified_date: str
    severity: str
    cvss_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    apple_related: bool
    affected_product: str
    detected_product: str
    detected_version: str
    affected_versions: list[str] = field(default_factory=list)
    applicability_confidence: str = "low"
    why_it_matters: str = ""
    recommended_action: str = ""
    update_guidance: str = ""
    references: list[str] = field(default_factory=list)
    status: str = "new"
    source: str = "nvd"
    local_match_evidence: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    snoozed_until: str = ""
    review_notes: str = ""
    source_trace: str = ""
    should_surface: bool = False

    def to_dict(self) -> dict[str, Any]:
        return json_safe(
            {
                "alert_id": self.alert_id,
                "cve_id": self.cve_id,
                "title": self.title,
                "published_date": self.published_date,
                "last_modified_date": self.last_modified_date,
                "severity": self.severity,
                "cvss_score": self.cvss_score,
                "epss_score": self.epss_score,
                "epss_percentile": self.epss_percentile,
                "kev": self.kev,
                "apple_related": self.apple_related,
                "affected_product": self.affected_product,
                "detected_product": self.detected_product,
                "detected_version": self.detected_version,
                "affected_versions": self.affected_versions,
                "applicability_confidence": self.applicability_confidence,
                "why_it_matters": self.why_it_matters,
                "recommended_action": self.recommended_action,
                "update_guidance": self.update_guidance,
                "references": self.references,
                "status": self.status,
                "source": self.source,
                "local_match_evidence": self.local_match_evidence,
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "snoozed_until": self.snoozed_until,
                "review_notes": self.review_notes,
                "source_trace": self.source_trace,
                "should_surface": self.should_surface,
            }
        )


class CveRadarEngine:
    def __init__(self, db: AuditDatabase, config: AuditConfig) -> None:
        self.db = db
        self.config = config
        self.cache_path = self.config.cache_dir / "cve_radar_catalog.json"
        self.updater = VulnerabilityCatalogUpdater(self.cache_path)

    def load_cached_state(self, *, limit: int = 200) -> dict[str, Any]:
        cached_catalog = self.db.latest_cve_radar_cache() or {"payload_json": {}}
        payload = cached_catalog.get("payload_json", {}) or {}
        alerts = self.db.list_cve_radar_alerts(limit=limit)
        inventory = self.db.latest_cve_radar_inventory() or {"payload_json": {}}
        return {
            "timestamp": cached_catalog.get("updated_at", ""),
            "catalog_update_status": payload.get("catalog_update_status", cached_catalog.get("source", "cached")),
            "sources_used": payload.get("data_sources_used", []),
            "cves_evaluated": len(payload.get("cves", [])),
            "applicable_cves": sum(1 for alert in alerts if alert.get("should_surface", False)),
            "kev_matches": sum(1 for alert in alerts if alert.get("kev", False)),
            "apple_updates_available": any(alert.get("apple_related", False) for alert in alerts),
            "alerts": alerts,
            "display_cards": group_alerts_for_display(alerts),
            "inventory": inventory.get("payload_json", {}),
        }

    def update_radar(self, *, current_scan_result: ScanResult | None = None, manual: bool = False, force: bool = False) -> dict[str, Any]:
        catalog = self._catalog(manual=manual, force=force)
        inventory = collect_local_inventory()
        self.db.record_cve_radar_cache(catalog, source=str(catalog.get("catalog_update_status", "catalog")), updated_at=str(catalog.get("timestamp", utc_now_iso())))
        self.db.record_cve_radar_inventory(inventory, source="local-inventory")
        alerts = self._build_alerts(catalog, inventory, current_scan_result)
        self._persist_alerts(alerts)
        summary = {
            "timestamp": catalog.get("timestamp", utc_now_iso()),
            "catalog_update_status": catalog.get("catalog_update_status", "cached"),
            "sources_used": catalog.get("data_sources_used", []),
            "cves_evaluated": len(catalog.get("cves", [])),
            "applicable_cves": sum(1 for alert in alerts if alert.should_surface),
            "kev_matches": sum(1 for alert in alerts if alert.kev),
            "apple_updates_available": any(alert.apple_related and alert.should_surface for alert in alerts),
            "alerts": [alert.to_dict() for alert in alerts],
            "display_cards": group_alerts_for_display([alert.to_dict() for alert in alerts]),
            "inventory": inventory,
            "cached": catalog.get("catalog_update_status") in {"offline-cache", "offline-rules"},
            "errors": catalog.get("errors", []),
        }
        return summary

    def mark_reviewed(self, alert_id: str, notes: str = "") -> None:
        alert = self.db.get_cve_radar_alert(alert_id)
        if not alert:
            return
        self.db.set_cve_radar_alert_status(alert_id, status="reviewed", notes=notes, action="reviewed", payload=alert)

    def snooze(self, alert_id: str, *, days: int | None = None, until_next_version_change: bool = False, notes: str = "") -> None:
        alert = self.db.get_cve_radar_alert(alert_id)
        if not alert:
            return
        snoozed_until = ""
        snooze_scope = ""
        version_marker = str(alert.get("detected_version", ""))
        if days is not None:
            snoozed_until = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            snooze_scope = "time"
        elif until_next_version_change:
            snooze_scope = "next_version_change"
        self.db.set_cve_radar_alert_status(
            alert_id,
            status="snoozed",
            notes=notes,
            snoozed_until=snoozed_until,
            snooze_scope=snooze_scope,
            version_marker=version_marker,
            action="snoozed",
            payload=alert,
        )

    def _catalog(self, *, manual: bool, force: bool) -> dict[str, Any]:
        cached = self.db.latest_cve_radar_cache()
        if cached and not force and not manual:
            updated_at = _utc_to_dt(str(cached.get("updated_at", "")))
            if updated_at and (datetime.now(timezone.utc) - updated_at).total_seconds() < UPDATE_INTERVAL_SECONDS:
                payload = cached.get("payload_json", {})
                payload.setdefault("catalog_update_status", "cached")
                return payload
        try:
            catalog = self.updater.update_catalog()
        except Exception:
            if cached:
                payload = dict(cached.get("payload_json", {}))
                payload["catalog_update_status"] = "offline-cache"
                payload.setdefault("errors", []).append("using cached CVE catalog after update failure")
                return payload
            return {
                "timestamp": utc_now_iso(),
                "data_sources_used": [],
                "kev": {},
                "epss": {},
                "cves": [],
                "apple_security_releases": [],
                "catalog_update_status": "offline-rules",
                "errors": ["CVE catalog update failed and no cache was available."],
            }
        return catalog

    def _persist_alerts(self, alerts: list[CveRadarAlert]) -> None:
        existing = {item.get("alert_id"): item for item in self.db.list_cve_radar_alerts(limit=1000)}
        reviews: dict[str, dict[str, Any]] = {}
        for review in self.db.list_cve_radar_reviews(limit=1000):
            alert_id = str(review.get("alert_id", ""))
            if alert_id and alert_id not in reviews:
                reviews[alert_id] = review
        seen_ids = set()
        for alert in alerts:
            seen_ids.add(alert.alert_id)
            previous = existing.get(alert.alert_id)
            review = reviews.get(alert.alert_id, {})
            snooze_scope = str(review.get("snooze_scope", ""))
            version_marker = str(review.get("version_marker", ""))
            if previous and previous.get("status") == "snoozed" and snooze_scope == "next_version_change" and version_marker and version_marker != str(alert.detected_version or ""):
                alert.status = "new"
                alert.review_notes = ""
                alert.snoozed_until = ""
            elif previous and previous.get("status") in {"reviewed", "snoozed"}:
                alert.status = str(previous.get("status", alert.status))
                alert.review_notes = str(previous.get("review_notes", ""))
                alert.first_seen = str(previous.get("first_seen", alert.first_seen))
            self.db.record_cve_radar_alerts([alert.to_dict()])
        for alert_id, previous in existing.items():
            if alert_id not in seen_ids and previous.get("status") != "resolved":
                previous["status"] = "resolved"
                previous["last_seen"] = utc_now_iso()
                self.db.record_cve_radar_alerts([previous])

    def _build_alerts(
        self,
        catalog: dict[str, Any],
        inventory: dict[str, Any],
        current_scan_result: ScanResult | None,
    ) -> list[CveRadarAlert]:
        products = inventory.get("products", [])
        alerts: dict[str, CveRadarAlert] = {}
        kev_map = catalog.get("kev", {})
        epss_map = catalog.get("epss", {})
        for item in catalog.get("cves", []):
            cve_id = str(item.get("cve_id", ""))
            if not cve_id:
                continue
            affected_products = item.get("affected_products", [])
            if not affected_products and not self._apple_related(item):
                continue
            matches = self._match_item(item, products)
            if not matches and not self._apple_related(item):
                continue
            cvss_score = item.get("cvss_score")
            severity = _severity_from_cvss(cvss_score)
            kev = cve_id in kev_map
            epss = epss_map.get(cve_id, {}) if isinstance(epss_map, dict) else {}
            apple_related = self._apple_related(item)
            source = "nvd"
            if apple_related:
                source = "apple"
            elif kev:
                source = "cisa_kev"
            elif float(epss.get("percentile", 0.0)) >= 0.90:
                source = "epss"
            applicability_confidence = self._confidence(matches)
            should_surface = self._should_surface(severity, kev, float(epss.get("percentile", 0.0)), applicability_confidence, apple_related)
            if not should_surface and applicability_confidence == "review-needed":
                # keep review-only matches in history, but do not surface by default
                pass
            if not should_surface and not matches and not apple_related:
                continue
            references = list(dict.fromkeys([ref for ref in item.get("references", []) if ref]))
            if kev:
                references.append(CISA_KEV_URL)
            if cve_id:
                references.append(f"{NVD_CVE_API_URL}?cveId={cve_id}")
            if epss:
                references.append(f"{FIRST_EPSS_API_URL}?cve={cve_id}")
            if apple_related:
                references.append(APPLE_SECURITY_RELEASES_URL)
            detected_product = matches[0]["product"] if matches else ("macOS" if apple_related else str(item.get("affected_products", [{}])[0].get("product", "")))
            detected_version = matches[0].get("version", "") if matches else ""
            local_match_evidence = matches
            alert = CveRadarAlert(
                alert_id=_hash_alert_id(cve_id),
                cve_id=cve_id,
                title=str(item.get("title") or cve_id),
                published_date=str(item.get("published_date", "")),
                last_modified_date=str(item.get("last_modified_date", "")),
                severity=severity,
                cvss_score=float(cvss_score) if cvss_score is not None else None,
                epss_score=float(epss.get("score", 0.0)) if epss else None,
                epss_percentile=float(epss.get("percentile", 0.0)) if epss else None,
                kev=kev,
                apple_related=apple_related,
                affected_product=str(item.get("affected_products", [{}])[0].get("product", "")) if item.get("affected_products") else "",
                detected_product=detected_product,
                detected_version=detected_version,
                affected_versions=[str(affected.get("version", "") or self._format_affected_versions(affected)) for affected in affected_products[:5]],
                applicability_confidence=applicability_confidence,
                why_it_matters=self._why_it_matters(item, detected_product, detected_version, apple_related),
                recommended_action=self._recommended_action(item, apple_related),
                update_guidance=self._update_guidance(item, apple_related),
                references=references,
                status="new" if should_surface else "resolved" if not matches and not apple_related else "new",
                source=source,
                local_match_evidence=local_match_evidence,
                source_trace=self._source_trace(item, matches, kev, epss, source),
                should_surface=should_surface,
            )
            if current_scan_result is not None:
                alert.local_match_evidence.extend(self._service_relevance(current_scan_result, detected_product))
            alerts[alert.alert_id] = alert
        return sorted(alerts.values(), key=self._sort_key, reverse=True)

    def _sort_key(self, alert: CveRadarAlert) -> tuple:
        kev = 1 if alert.kev else 0
        severity = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(alert.severity, 0)
        epss = int((alert.epss_percentile or 0.0) * 100)
        exact = 1 if alert.applicability_confidence == "high" else 0
        apple = 1 if alert.apple_related else 0
        freshness = _utc_to_dt(alert.published_date) or datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (kev, severity, epss, exact, apple, freshness.timestamp())

    def _format_affected_versions(self, affected: dict[str, Any]) -> str:
        parts = []
        for key in ["version", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"]:
            if affected.get(key):
                parts.append(f"{key}={affected[key]}")
        return ", ".join(parts)

    def _service_relevance(self, scan_result: ScanResult, detected_product: str) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        risky_ports = {2375, 5432, 3306, 27017, 6379, 9200, 8000, 8080, 8888}
        open_ports = {
            int(item.get("port") if isinstance(item, dict) else getattr(item, "port", 0))
            for item in scan_result.artifacts.get("ports", {}).get("listening", [])
            if (item.get("port") if isinstance(item, dict) else getattr(item, "port", None)) is not None
        }
        if detected_product and open_ports.intersection(risky_ports):
            evidence.append(
                {
                    "match_type": "service-relevance",
                    "product": detected_product,
                    "details": "A risky local service port is listening on this Mac, so the CVE may matter sooner if the service is exposed beyond localhost.",
                    "open_ports": sorted(open_ports.intersection(risky_ports)),
                }
            )
        return evidence

    def _confidence(self, matches: list[dict[str, Any]]) -> str:
        if not matches:
            return "review-needed"
        best = matches[0]
        match_type = str(best.get("match_type", ""))
        if match_type == "exact":
            return "high"
        if match_type in {"version-uncertain", "exact-product"}:
            return "medium"
        if match_type == "family":
            return "low"
        return str(best.get("applicability_confidence", "review-needed"))

    def _should_surface(self, severity: str, kev: bool, epss_percentile: float, applicability_confidence: str, apple_related: bool) -> bool:
        if apple_related and severity in SURFACE_SEVERITIES:
            return True
        if severity == "critical" and applicability_confidence in {"high", "medium"}:
            return True
        if severity == "high" and kev:
            return True
        if severity == "high" and epss_percentile >= 0.90 and applicability_confidence in {"high", "medium"}:
            return True
        return False

    def _apple_related(self, item: dict[str, Any]) -> bool:
        text = f"{item.get('description', '')} {' '.join(item.get('references', []))}".lower()
        if "apple" in text or "macos" in text:
            return True
        for affected in item.get("affected_products", []):
            if normalize_product_name(affected.get("product", "")) in APPLE_PRODUCTS:
                return True
        return False

    def _match_item(self, item: dict[str, Any], inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for affected in item.get("affected_products", []):
            affected_product = normalize_product_name(affected.get("product", ""))
            affected_vendor = normalize_product_name(affected.get("vendor", ""))
            aliases = _family_aliases(affected.get("product", ""))
            for installed in inventory:
                installed_product = normalize_product_name(installed.get("product", ""))
                installed_family = normalize_product_name(installed.get("family", ""))
                installed_vendor = normalize_product_name(installed.get("vendor", ""))
                product_match = installed_product == affected_product or installed_family in aliases or affected_product in _family_aliases(installed.get("product", ""))
                vendor_match = not affected_vendor or not installed_vendor or affected_vendor == installed_vendor
                if not product_match or not vendor_match:
                    continue
                version = str(installed.get("version", "") or "")
                affected_versions = [affected]
                version_match = version_matches_affected_range(version, affected_versions) if version else None
                if version and version_match is False:
                    continue
                match_type = "exact"
                if not version:
                    match_type = "version-uncertain"
                elif version_match is None:
                    match_type = "exact-product"
                match = {
                    "product": str(installed.get("product", "")),
                    "version": version,
                    "source": str(installed.get("source", "")),
                    "family": str(installed.get("family", "")),
                    "vendor": str(installed.get("vendor", "")),
                    "path": str(installed.get("path", "")),
                    "match_type": match_type,
                    "affected_product": str(affected.get("product", "")),
                    "affected_vendor": str(affected.get("vendor", "")),
                    "affected_versions": self._format_affected_versions(affected),
                    "applicability_confidence": self._match_confidence(match_type, version, version_match),
                    "detail": f"{installed.get('product', '')} {version or 'version unavailable'} matched {affected.get('product', '')}",
                }
                matches.append(match)
        if not matches and self._apple_related(item):
            matches.append(
                {
                    "product": "macOS",
                    "version": str(platform.mac_ver()[0] or ""),
                    "source": "platform",
                    "family": "apple",
                    "vendor": "apple",
                    "path": "",
                    "match_type": "family",
                    "affected_product": str(item.get("affected_products", [{}])[0].get("product", "")) if item.get("affected_products") else "Apple",
                    "affected_vendor": "apple",
                    "affected_versions": "",
                    "applicability_confidence": "review-needed",
                    "detail": "Apple family relevance detected from the local platform and browser family.",
                }
            )
        return matches

    def _match_confidence(self, match_type: str, version: str, version_match: bool | None) -> str:
        if match_type == "exact" and version and version_match is True:
            return "high"
        if match_type == "version-uncertain":
            return "review-needed"
        if match_type == "exact-product":
            return "medium"
        if match_type == "family":
            return "low"
        return "review-needed"

    def _why_it_matters(self, item: dict[str, Any], product: str, version: str, apple_related: bool) -> str:
        title = str(item.get("description", "")).strip()
        if apple_related:
            return f"{title or item.get('cve_id', 'Apple CVE')} may affect macOS, Safari, WebKit, or Xcode on this Mac."
        if product:
            return f"{title or item.get('cve_id', 'CVE')} may apply to the installed {product} {version or 'version unknown'}."
        return f"{title or item.get('cve_id', 'CVE')} may be relevant to a detected product family on this Mac."

    def _recommended_action(self, item: dict[str, Any], apple_related: bool) -> str:
        if apple_related:
            return "Review Apple Security Release notes, then update macOS or the affected Apple component through System Settings > General > Software Update."
        return "Confirm the installed version locally, review the vendor advisory, and update only if the affected version range matches."

    def _update_guidance(self, item: dict[str, Any], apple_related: bool) -> str:
        if apple_related:
            return "System Settings > General > Software Update. If the build is managed, follow the approved enterprise update path and confirm the matching Apple security release notes."
        product = str(item.get("affected_products", [{}])[0].get("product", "")) if item.get("affected_products") else ""
        if product:
            return f"Verify `{product} --version` or the product's About dialog, then follow the vendor's official updater or package manager if the CVE applies."
        return "Review the product vendor's security bulletin and confirm whether the installed version is affected before updating."

def _source_trace(self, item: dict[str, Any], matches: list[dict[str, Any]], kev: bool, epss: dict[str, Any], source: str) -> str:
        parts = [
            f"source={source}",
            f"cve_id={item.get('cve_id', '')}",
            f"severity={_severity_from_cvss(item.get('cvss_score'))}",
            f"kev={'yes' if kev else 'no'}",
            f"epss={epss.get('percentile', '')}",
        ]
        if matches:
            parts.append(f"match={matches[0].get('product', '')} {matches[0].get('version', '')}".strip())
        return "; ".join(part for part in parts if part)


APPLE_SECURITY_FAMILY_KEYS = {"macos", "safari", "webkit", "xcode", "commandlinetools", "apple"}
APPLE_MAC_FOCUSED_FAMILY_KEYS = {"macos", "osx", "safari", "webkit", "xcode", "commandlinetools", "commandlinetool"}
APPLE_ECOSYSTEM_ONLY_KEYS = {"iphone", "iphoneos", "ios", "ipad", "ipados", "watchos", "tvos", "visionos"}
APPLE_FORECAST_LEVELS = {"clear": 0, "watch": 1, "elevated": 2, "urgent": 3, "critical": 4}
APPLE_FORECAST_LEVEL_FOR_SEVERITY = {"critical": "urgent", "high": "elevated", "medium": "watch", "low": "watch", "info": "clear"}
SEVERITY_RANKS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
APPLE_FORECAST_DEFAULT_ACTIVE_DAYS = 90
APPLE_FORECAST_MAX_ACTIVE_DAYS = 180
APPLE_FORECAST_MIN_YEAR = 2020


def _forecast_level_rank(level: str) -> int:
    return APPLE_FORECAST_LEVELS.get(level, 0)


def _forecast_level_max(left: str, right: str) -> str:
    return left if _forecast_level_rank(left) >= _forecast_level_rank(right) else right


def _severity_max(left: str, right: str) -> str:
    return left if SEVERITY_RANKS.get(left, 0) >= SEVERITY_RANKS.get(right, 0) else right


def _version_is_older(installed: str, fixed: str) -> bool | None:
    if not installed or not fixed:
        return None
    try:
        return compare_versions(installed, fixed) < 0
    except Exception:
        return None


def _advisory_dt(item: dict[str, Any]) -> datetime | None:
    for key in ("advisory_date", "published_date", "published", "last_modified_date", "lastModified"):
        parsed = _utc_to_dt(str(item.get(key, "")))
        if parsed:
            return parsed
    return None


def collect_apple_security_inventory() -> dict[str, Any]:
    inventory = {
        "collected_at": utc_now_iso(),
        "platform": platform.platform(),
        "architecture": _run_command(["/usr/bin/arch"], timeout=4) or platform.machine(),
        "device_model": _run_command(["/usr/sbin/sysctl", "-n", "hw.model"], timeout=4),
        "macos_version": "",
        "macos_build": "",
        "safari_version": "",
        "safari_build": "",
        "safari_detection_method": "not detected",
        "webkit_version": "",
        "xcode_version": "",
        "command_line_tools_version": "",
        "apple_apps": [],
        "software_update_available": False,
        "software_update_items": [],
        "software_update_check_status": "not checked",
        "software_update_error": "",
        "privacy_guarantee": "Safari Private Browsing does not affect this forecast. The forecast uses installed Safari/macOS version and Apple advisory/update data only.",
        "why_no_cards": "",
        "products": [],
        "summary": {},
    }

    sw_vers_version = _run_command(["/usr/bin/sw_vers", "-productVersion"], timeout=4)
    sw_vers_build = _run_command(["/usr/bin/sw_vers", "-buildVersion"], timeout=4)
    inventory["macos_version"] = sw_vers_version
    inventory["macos_build"] = sw_vers_build

    def add(product: str, version: str, *, family: str, source: str, vendor: str = "apple", notes: str = "") -> None:
        if not product:
            return
        inventory["products"].append(
            {
                "product": product,
                "normalized_product": normalize_product_name(product),
                "version": version,
                "family": family,
                "source": source,
                "vendor": vendor,
                "notes": notes,
            }
        )

    if sw_vers_version:
        add("macOS", f"{sw_vers_version} ({sw_vers_build})" if sw_vers_build else sw_vers_version, family="macos", source="sw_vers")

    safari_info_path = "/Applications/Safari.app/Contents/Info"
    safari_version = _run_command(["/usr/bin/defaults", "read", safari_info_path, "CFBundleShortVersionString"], timeout=5)
    safari_build = _run_command(["/usr/bin/defaults", "read", safari_info_path, "CFBundleVersion"], timeout=5)
    if safari_version:
        safari_version = _parse_version(safari_version) or safari_version[:80]
        inventory["safari_detection_method"] = "Info.plist CFBundleShortVersionString via defaults"
    else:
        mdls_text = _run_command(["/usr/bin/mdls", "-name", "kMDItemVersion", "/Applications/Safari.app"], timeout=5)
        safari_version = _parse_version(mdls_text) or ""
        if safari_version:
            inventory["safari_detection_method"] = "Spotlight metadata kMDItemVersion via mdls"
    if safari_version:
        inventory["safari_version"] = safari_version
        inventory["safari_build"] = _parse_version(safari_build) or safari_build[:80]
        add("Safari", safari_version, family="safari", source=inventory["safari_detection_method"])

    if inventory["safari_version"]:
        inventory["webkit_version"] = inventory["safari_version"]
        add("WebKit", inventory["safari_version"], family="webkit", source="Safari installed version", notes="Forecast uses installed Safari metadata only; no browsing state is inspected.")

    xcode_text = _run_command(["/usr/bin/xcodebuild", "-version"], timeout=8)
    if xcode_text:
        xcode_version = extract_version(xcode_text) or xcode_text.splitlines()[0][:80]
        inventory["xcode_version"] = xcode_version
        add("Xcode", xcode_version, family="xcode", source="xcodebuild")
    clt_text = _run_command(["/usr/sbin/pkgutil", "--pkg-info=com.apple.pkg.CLTools_Executables"], timeout=6)
    if clt_text:
        clt_version = extract_version(clt_text) or clt_text[:80]
        inventory["command_line_tools_version"] = clt_version
        add("Command Line Tools", clt_version, family="commandlinetools", source="pkgutil")

    apple_app_names = ["Mail", "Messages", "Notes", "Calendar", "FaceTime", "Preview", "TextEdit", "Reminders", "System Settings"]
    for name in apple_app_names:
        app_path = Path("/System/Applications") / f"{name}.app"
        if app_path.exists():
            add(name, "", family="apple_app", source="filesystem", notes="Apple-installed app detected")
            inventory["apple_apps"].append(name)

    update_text, update_ok = _run_command_result(["/usr/sbin/softwareupdate", "-l"], timeout=20)
    if update_ok:
        items = [line.strip("* ").strip() for line in update_text.splitlines() if line.strip().startswith("*")]
        inventory["software_update_available"] = bool(items)
        inventory["software_update_items"] = items[:25]
        inventory["software_update_check_status"] = "updates available" if items else "no updates reported"
    else:
        inventory["software_update_check_status"] = "failed"
        inventory["software_update_error"] = update_text[:300]

    inventory["summary"] = {
        "product_count": len(inventory["products"]),
        "apple_app_count": len(inventory["apple_apps"]),
        "software_update_available": inventory["software_update_available"],
        "safari_detection_method": inventory["safari_detection_method"],
        "software_update_check_status": inventory["software_update_check_status"],
    }
    return inventory


def group_forecast_cards_for_display(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: list[dict[str, Any]] = []
    by_title: dict[str, dict[str, Any]] = {}
    for card in cards:
        title = str(card.get("title", "Apple Security Forecast")).strip() or "Apple Security Forecast"
        category = str(card.get("category", "")).strip()
        group_key = f"{category}:{title}" if category else title
        existing = by_title.get(group_key)
        if existing is None:
            card_copy = dict(card)
            card_copy.setdefault("cves", [])
            card_copy.setdefault("kev_cves", [])
            card_copy.setdefault("epss_high_cves", [])
            card_copy["alerts"] = [dict(card)]
            by_title[group_key] = card_copy
            continue
        existing.setdefault("cves", []).extend(card.get("cves", []))
        existing.setdefault("kev_cves", []).extend(card.get("kev_cves", []))
        existing.setdefault("epss_high_cves", []).extend(card.get("epss_high_cves", []))
        existing["alerts"].append(dict(card))
        existing["cve_count"] = len({*existing.get("cves", []), *card.get("cves", [])})
        existing["kev_count"] = len({*existing.get("kev_cves", []), *card.get("kev_cves", [])})
        existing["forecast_level"] = _forecast_level_max(str(existing.get("forecast_level", "clear")), str(card.get("forecast_level", "clear")))
        existing["highest_severity"] = _severity_max(str(existing.get("highest_severity", "info")), str(card.get("highest_severity", "info")))
        existing["why_shown_to_you"] = str(existing.get("why_shown_to_you", ""))
        existing["status"] = str(existing.get("status", "new"))
        existing["snooze_until"] = str(existing.get("snooze_until", ""))
        existing["affected_products"] = sorted({*existing.get("affected_products", []), *(card.get("affected_products", []))})
    grouped.extend(by_title.values())
    return sorted(grouped, key=lambda item: (_forecast_level_rank(str(item.get("forecast_level", "clear"))), item.get("kev_count", 0), item.get("cve_count", 0)), reverse=True)


def _normalize_card_list(items: Any) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            normalized.append(item)
        elif hasattr(item, "to_dict"):
            try:
                candidate = item.to_dict()
            except Exception:
                continue
            if isinstance(candidate, dict):
                normalized.append(candidate)
    return normalized


class AppleSecurityForecastCard:
    def __init__(self, **kwargs: Any) -> None:
        self.card_id = str(kwargs.get("card_id", ""))
        self.title = str(kwargs.get("title", ""))
        self.category = str(kwargs.get("category", "macOS"))
        self.forecast_level = str(kwargs.get("forecast_level", "clear"))
        self.simulated = bool(kwargs.get("simulated", False))
        self.affected_local_product = str(kwargs.get("affected_local_product", ""))
        self.detected_version = str(kwargs.get("detected_version", ""))
        self.fixed_version = str(kwargs.get("fixed_version", ""))
        self.cves = list(kwargs.get("cves", []))
        self.kev_cves = list(kwargs.get("kev_cves", []))
        self.epss_high_cves = list(kwargs.get("epss_high_cves", []))
        self.applicability = str(kwargs.get("applicability", "review_needed"))
        self.confidence = str(kwargs.get("confidence", "review-needed"))
        self.why_shown = str(kwargs.get("why_shown", ""))
        self.what_to_do = str(kwargs.get("what_to_do", ""))
        self.update_path = str(kwargs.get("update_path", ""))
        self.references = list(kwargs.get("references", []))
        self.status = str(kwargs.get("status", "new"))
        self.snooze_until = str(kwargs.get("snooze_until", ""))
        self.forecast_id = str(kwargs.get("forecast_id", ""))
        self.summary = str(kwargs.get("summary", ""))
        self.affected_products = list(kwargs.get("affected_products", []))
        self.generated_at = str(kwargs.get("generated_at", utc_now_iso()))
        self.cve_count = int(kwargs.get("cve_count", len(self.cves)))
        self.kev_count = int(kwargs.get("kev_count", len(self.kev_cves)))
        self.highest_severity = str(kwargs.get("highest_severity", "info"))
        self.source = str(kwargs.get("source", "apple"))
        self.previous_level = str(kwargs.get("previous_level", ""))
        self.next_check_at = str(kwargs.get("next_check_at", ""))
        self.detected_product = self.affected_local_product
        self.source_trace = str(kwargs.get("source_trace", ""))
        self.card_type = str(kwargs.get("card_type", "forecast"))
        self.false_positive_review = kwargs.get("false_positive_review", {})
        self.planning_guidance = str(kwargs.get("planning_guidance", ""))
        self.forecast_phrase = str(kwargs.get("forecast_phrase", ""))

    def to_dict(self) -> dict[str, Any]:
        payload = json_safe(self.__dict__)
        payload.setdefault("cve_ids", list(self.cves))
        payload.setdefault("kev", bool(self.kev_cves))
        payload.setdefault("applicability_confidence", self.confidence)
        payload.setdefault("why_shown_to_you", self.why_shown)
        payload.setdefault("recommended_action", self.what_to_do)
        payload.setdefault("update_guidance", self.update_path)
        payload.setdefault("detected_product", self.affected_local_product)
        payload.setdefault("detected_version", self.detected_version)
        payload.setdefault("source", self.source)
        payload.setdefault("severity", self.highest_severity)
        payload.setdefault("simulated", self.simulated)
        payload.setdefault("first_seen", self.generated_at)
        payload.setdefault("last_seen", self.generated_at)
        payload.setdefault("cve_id", self.cves[0] if self.cves else "")
        return payload


class AppleSecurityForecast:
    def __init__(self, **kwargs: Any) -> None:
        self.forecast_id = str(kwargs.get("forecast_id", ""))
        self.generated_at = str(kwargs.get("generated_at", utc_now_iso()))
        self.level = str(kwargs.get("level", "clear"))
        self.summary = str(kwargs.get("summary", ""))
        self.state_text = str(kwargs.get("state_text", ""))
        self.why_no_cards = str(kwargs.get("why_no_cards", ""))
        self.last_error = str(kwargs.get("last_error", ""))
        self.affected_products = list(kwargs.get("affected_products", []))
        self.cve_count = int(kwargs.get("cve_count", 0))
        self.kev_count = int(kwargs.get("kev_count", 0))
        self.highest_severity = str(kwargs.get("highest_severity", "info"))
        self.recommended_action = str(kwargs.get("recommended_action", ""))
        self.cards = list(kwargs.get("cards", []))
        self.previous_level = str(kwargs.get("previous_level", ""))
        self.next_check_at = str(kwargs.get("next_check_at", ""))
        self.source_age_hours = int(kwargs.get("source_age_hours", 0))
        self.cache_age_text = str(kwargs.get("cache_age_text", ""))
        self.should_announce = bool(kwargs.get("should_announce", False))
        self.sources_used = list(kwargs.get("sources_used", []))
        self.inventory = kwargs.get("inventory", {})
        self.catalog_update_status = str(kwargs.get("catalog_update_status", "cached"))
        self.errors = list(kwargs.get("errors", []))
        self.simulated = bool(kwargs.get("simulated", False))
        self.source_mode = str(kwargs.get("source_mode", "live"))
        self.apple_source_status = str(kwargs.get("apple_source_status", ""))
        self.kev_source_status = str(kwargs.get("kev_source_status", ""))
        self.nvd_source_status = str(kwargs.get("nvd_source_status", ""))
        self.epss_source_status = str(kwargs.get("epss_source_status", ""))
        self.filtered_non_apple_cves_count = int(kwargs.get("filtered_non_apple_cves_count", 0))
        self.hidden_review_needed_count = int(kwargs.get("hidden_review_needed_count", 0))
        self.last_successful_update_at = str(kwargs.get("last_successful_update_at", ""))
        self.card_count = int(kwargs.get("card_count", len(self.cards)))
        self.diagnostics = kwargs.get("diagnostics", {})

    def to_dict(self) -> dict[str, Any]:
        payload = json_safe(self.__dict__)
        payload["cards"] = [card.to_dict() if hasattr(card, "to_dict") else json_safe(card) for card in self.cards]
        payload["alerts"] = [card.to_dict() if hasattr(card, "to_dict") else json_safe(card) for card in self.cards]
        payload["display_cards"] = group_forecast_cards_for_display([card.to_dict() if hasattr(card, "to_dict") else json_safe(card) for card in self.cards])
        payload.setdefault("forecast_level", self.level)
        payload.setdefault("timestamp", self.generated_at)
        payload.setdefault("applicable_cves", len(payload["display_cards"]))
        payload.setdefault("kev_matches", self.kev_count)
        payload.setdefault("apple_updates_available", self.level in {"elevated", "urgent", "critical"})
        payload.setdefault("state_text", self.state_text)
        payload.setdefault("why_no_cards", self.why_no_cards)
        payload.setdefault("last_error", self.last_error)
        payload.setdefault("cve_ids", [cve for card in payload["display_cards"] for cve in card.get("cves", [])])
        payload.setdefault("kev_cves", [cve for card in payload["display_cards"] for cve in card.get("kev_cves", [])])
        payload.setdefault("why_shown_to_you", self.summary)
        payload.setdefault("recommended_action", self.recommended_action)
        payload.setdefault("update_guidance", "")
        payload.setdefault("applicability_confidence", "review-needed")
        payload.setdefault("source", "apple")
        payload.setdefault("simulated", self.simulated)
        payload.setdefault("source_mode", self.source_mode)
        payload.setdefault("apple_source_status", self.apple_source_status)
        payload.setdefault("kev_source_status", self.kev_source_status)
        payload.setdefault("nvd_source_status", self.nvd_source_status)
        payload.setdefault("epss_source_status", self.epss_source_status)
        payload.setdefault("filtered_non_apple_cves_count", self.filtered_non_apple_cves_count)
        payload.setdefault("hidden_review_needed_count", self.hidden_review_needed_count)
        payload.setdefault("last_successful_update_at", self.last_successful_update_at)
        payload.setdefault("card_count", self.card_count)
        payload.setdefault("diagnostics", self.diagnostics)
        return payload


class AppleSecurityForecastEngine:
    def __init__(self, db: AuditDatabase, config: AuditConfig) -> None:
        self.db = db
        self.config = config
        self.cache_path = self.config.cache_dir / "apple_security_forecast_catalog.json"
        self.updater = VulnerabilityCatalogUpdater(self.cache_path)
        self.update_interval_seconds = max(60, int(getattr(self.config, "update_interval_hours", 6) or 6) * 3600)
        self.auto_update_enabled = bool(getattr(self.config, "auto_update_apple_security_forecast", False))
        self._last_diagnostics: dict[str, int] = {}

    def load_cached_state(self, *, limit: int = 200) -> dict[str, Any]:
        forecast = self.db.latest_apple_security_forecast()
        cards = _normalize_card_list(self.db.list_apple_security_forecast_cards(limit=limit))
        forecast_payload = forecast.get("payload_json", {}) if forecast else {}
        nested_payload = forecast_payload.get("payload_json", {}) if isinstance(forecast_payload.get("payload_json", {}), dict) else {}
        if _is_simulated_forecast_payload(forecast_payload):
            forecast = None
            forecast_payload = {}
            cards = []
        cards = [card for card in cards if not card.get("simulated") and not str(card.get("source_mode", "")).startswith("demo")]
        if forecast_payload and not cards:
            cards = _normalize_card_list(forecast_payload.get("cards", [])) or _normalize_card_list(forecast_payload.get("display_cards", []))
            cards = [card for card in cards if not card.get("simulated") and not str(card.get("source_mode", "")).startswith("demo")]
        inventory = forecast_payload.get("inventory", {})
        if not inventory:
            cached_inventory = self.db.latest_apple_security_cve_cache()
            inventory = cached_inventory[-1]["payload_json"] if cached_inventory else {}
        review_state = self.db.latest_apple_security_review_state()
        legacy = self.db.latest_cve_radar_cache()
        legacy_payload = legacy.get("payload_json", {}) if legacy else {}
        if not forecast and legacy_payload:
            cards = _normalize_card_list(legacy_payload.get("display_cards", [])) or _normalize_card_list(group_alerts_for_display(legacy_payload.get("alerts", [])))
        display_cards = group_forecast_cards_for_display(cards)
        hidden_review_needed = sum(1 for card in cards if str(card.get("applicability", card.get("applicability_confidence", ""))) == "review_needed")
        state_text, why_no_cards = self._state_and_explanation(forecast_payload if forecast else legacy_payload, cards)
        LOGGER.info(
            "Apple Security Forecast loaded from cache forecast_id=%s cards=%d state=%s",
            forecast.get("forecast_id", "") if forecast else legacy.get("cache_key", "") if legacy else "",
            len(display_cards),
            state_text,
        )
        return {
            "timestamp": forecast.get("generated_at", "") if forecast else legacy.get("updated_at", "") if legacy else "",
            "catalog_update_status": forecast_payload.get("catalog_update_status", "cached") if forecast else legacy_payload.get("catalog_update_status", legacy.get("source", "cached") if legacy else "cached"),
            "sources_used": forecast_payload.get("sources_used", []) if forecast else legacy_payload.get("sources_used", []),
            "cves_evaluated": forecast_payload.get("cve_count", legacy_payload.get("cves_evaluated", 0)) if forecast else legacy_payload.get("cves_evaluated", 0),
            "applicable_cves": len(display_cards),
            "kev_matches": sum(1 for card in cards if card.get("kev_cves") or card.get("kev")),
            "apple_updates_available": any(card.get("forecast_level") in {"elevated", "urgent", "critical"} for card in cards) or bool(forecast_payload.get("catalog_update_status") == "updated" and inventory.get("software_update_available")),
            "alerts": cards,
            "display_cards": display_cards,
            "inventory": inventory,
            "review_state": review_state,
            "state_text": state_text,
            "why_no_cards": why_no_cards,
            "hidden_review_needed_count": hidden_review_needed,
            "filtered_non_apple_cves_count": max(0, int(legacy_payload.get("cves_evaluated", 0)) - len(cards)) if legacy_payload else 0,
            "diagnostics": forecast_payload.get("diagnostics", {}),
            "last_error": ", ".join(forecast.get("errors", [])) if forecast else ", ".join(legacy_payload.get("errors", [])) if legacy_payload else "",
            "simulated": False,
            "source_mode": "live",
            "apple_source_status": str(forecast_payload.get("apple_source_status", legacy.get("source", "") if legacy else "")),
            "kev_source_status": str(forecast_payload.get("kev_source_status", "")),
            "nvd_source_status": str(forecast_payload.get("nvd_source_status", "")),
            "epss_source_status": str(forecast_payload.get("epss_source_status", "")),
            "last_successful_update_at": str(forecast.get("generated_at", "") if forecast else legacy.get("updated_at", "") if legacy else ""),
            "card_count": len(cards),
        }

    def _state_and_explanation(self, payload: dict[str, Any], cards: list[dict[str, Any]]) -> tuple[str, str]:
        if not payload and not cards:
            return "Forecast not checked yet", "No Apple Security Forecast has been checked yet."
        if payload.get("last_error") and not cards:
            if payload.get("catalog_update_status") in {"offline-cache", "offline-rules"}:
                return "Unable to update forecast — using cache" if payload.get("timestamp") else "Unable to update forecast — no cache available", str(payload.get("last_error", ""))
            return "Unable to update forecast — no cache available", str(payload.get("last_error", ""))
        if not cards:
            inventory = payload.get("inventory", {}) if isinstance(payload.get("inventory", {}), dict) else {}
            if payload.get("catalog_update_status") in {"offline-rules"}:
                return "Unable to update forecast — no cache available", "Offline and no cache is available."
            if str(inventory.get("software_update_check_status", "")) == "failed":
                return "Unable to update forecast — using cache", "Software update check failed; using cached advisory data."
            if not inventory.get("safari_version") and payload.get("safari_required"):
                return "Watch", "Safari version could not be detected."
            if int(payload.get("hidden_review_needed_count", 0)) > 0:
                return "Watch", "Only review-needed items were found and are hidden by default."
            if str(payload.get("why_no_cards", "")):
                return str(payload.get("state_text", "Clear")), str(payload.get("why_no_cards", ""))
            return "Clear — no applicable Apple security updates found", "No applicable Apple security advisories matched this Mac."
        level = str(payload.get("level") or payload.get("forecast_level") or "watch")
        if level == "critical":
            return "Update Today", "A known-exploited Apple issue appears to match this Mac, and an Apple update path is available."
        if level == "urgent":
            return "Plan Update", "A known-exploited or high-impact Apple item may apply. Verify Software Update and plan a timely update."
        if level == "elevated":
            return "Check Today", "Apple security update guidance may apply. Check Software Update when convenient today."
        if level == "watch":
            return "Watch", "Apple advisory data exists, but the local match is not strong enough to recommend immediate action."
        return "Clear — no applicable Apple security updates found", "No applicable Apple security forecast cards were found."

    def _source_status(self, catalog: dict[str, Any]) -> dict[str, str]:
        sources = set(catalog.get("data_sources_used", []))
        errors = catalog.get("errors", [])
        return {
            "apple": "updated" if "Apple security releases" in sources else "degraded" if any(str(item).startswith("apple:") for item in errors) else "cache",
            "kev": "updated" if "CISA KEV" in sources else "degraded" if any(str(item).startswith("kev:") for item in errors) else "cache",
            "nvd": "updated" if "NVD CVE API" in sources else "degraded" if any(str(item).startswith("nvd:") for item in errors) else "cache",
            "epss": "updated" if "FIRST EPSS" in sources else "degraded" if any(str(item).startswith("epss:") for item in errors) else "cache",
        }

    def update_radar(
        self,
        *,
        current_scan_result: ScanResult | None = None,
        manual: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        LOGGER.info("Apple Security Forecast update requested manual=%s force=%s", manual, force)
        forecast = self.generate_forecast(current_scan_result=current_scan_result, manual=manual, force=force)
        self.db.record_apple_security_forecast(forecast.to_dict())
        self.db.record_apple_security_forecast_cards([_card_payload(card) for card in forecast.cards])
        LOGGER.info("Apple Security Forecast stored forecast_id=%s cards=%d level=%s simulated=%s", forecast.forecast_id, len(forecast.cards), forecast.level, forecast.simulated)
        return forecast.to_dict()

    def generate_forecast(
        self,
        *,
        current_scan_result: ScanResult | None = None,
        manual: bool = False,
        force: bool = False,
    ) -> AppleSecurityForecast:
        cached = self.db.latest_apple_security_forecast()
        previous_level = str(cached.get("level", "clear")) if cached else "clear"
        if cached and (_is_simulated_forecast_payload(cached) or _is_simulated_forecast_payload(cached.get("payload_json", {}) if isinstance(cached.get("payload_json", {}), dict) else {})):
            self.purge_simulated_forecasts()
            cached = None
            previous_level = "clear"
        if cached and not force and not manual and not self.auto_update_enabled:
            payload = dict(cached.get("payload_json", {}))
            payload.setdefault("cards", self.db.list_apple_security_forecast_cards(limit=200))
            payload["cards"] = _normalize_card_list(payload.get("cards", [])) or _normalize_card_list(payload.get("display_cards", [])) or _normalize_card_list(payload.get("alerts", []))
            payload.setdefault("forecast_id", str(cached.get("forecast_id", "")))
            payload.setdefault("generated_at", str(cached.get("generated_at", "")))
            payload.setdefault("level", str(cached.get("level", "clear")))
            payload.setdefault("previous_level", previous_level)
            payload.setdefault("next_check_at", str(cached.get("next_check_at", "")))
            payload.setdefault("state_text", str(payload.get("state_text", "")))
            payload.setdefault("why_no_cards", str(payload.get("why_no_cards", "")))
            payload.setdefault("last_error", str(payload.get("last_error", "")))
            LOGGER.info(
                "Apple Security Forecast using cached forecast forecast_id=%s cards=%d",
                cached.get("forecast_id", ""),
                len(payload.get("cards", [])),
            )
            return AppleSecurityForecast(**payload)
        if cached and not force and not manual and self.auto_update_enabled:
            cached_at = _utc_to_dt(str(cached.get("generated_at", "")))
            if cached_at and (datetime.now(timezone.utc) - cached_at).total_seconds() < self.update_interval_seconds:
                payload = dict(cached.get("payload_json", {}))
                payload.setdefault("cards", self.db.list_apple_security_forecast_cards(limit=200))
                payload["cards"] = _normalize_card_list(payload.get("cards", [])) or _normalize_card_list(payload.get("display_cards", [])) or _normalize_card_list(payload.get("alerts", []))
                payload.setdefault("forecast_id", str(cached.get("forecast_id", "")))
                payload.setdefault("generated_at", str(cached.get("generated_at", "")))
                payload.setdefault("level", str(cached.get("level", "clear")))
                payload.setdefault("previous_level", previous_level)
                payload.setdefault("next_check_at", str(cached.get("next_check_at", "")))
                payload.setdefault("state_text", str(payload.get("state_text", "")))
                payload.setdefault("why_no_cards", str(payload.get("why_no_cards", "")))
                payload.setdefault("last_error", str(payload.get("last_error", "")))
                LOGGER.info(
                    "Apple Security Forecast using fresh cache forecast_id=%s cards=%d",
                    cached.get("forecast_id", ""),
                    len(payload.get("cards", [])),
                )
                return AppleSecurityForecast(**payload)

        LOGGER.info("Apple Security Forecast collecting Apple inventory")
        catalog = self._catalog(manual=manual, force=force)
        LOGGER.info("Apple Security Forecast catalog status=%s sources=%s errors=%d", catalog.get("catalog_update_status", "unknown"), catalog.get("data_sources_used", []), len(catalog.get("errors", [])))
        inventory = collect_apple_security_inventory()
        LOGGER.info("Apple Security Forecast inventory collected products=%d macOS=%s Safari=%s WebKit=%s Xcode=%s", len(inventory.get("products", [])), inventory.get("macos_version", ""), inventory.get("safari_version", ""), inventory.get("webkit_version", ""), inventory.get("xcode_version", ""))
        cards = self._build_cards(catalog, inventory, current_scan_result)
        cards = self._apply_review_state(cards)
        cards = group_forecast_cards_for_display([card.to_dict() for card in cards])
        forecast_level = self._forecast_level(cards, inventory)
        current_level = forecast_level
        should_announce = _forecast_level_rank(current_level) > _forecast_level_rank(previous_level) and current_level in {"elevated", "urgent", "critical"}
        summary = self._summary_text(current_level, cards, inventory)
        affected_products = sorted({str(card.get("affected_local_product", "")) for card in cards if card.get("affected_local_product")})
        highest_severity = "info"
        for card in cards:
            highest_severity = _severity_max(highest_severity, str(card.get("highest_severity", "info")))
        state_text, why_no_cards = self._state_and_explanation(
            {
                "level": current_level,
                "catalog_update_status": catalog.get("catalog_update_status", "updated"),
                "last_error": ", ".join(catalog.get("errors", [])),
                "why_no_cards": summary,
                "inventory": inventory,
            },
            cards,
        )
        forecast = AppleSecurityForecast(
            forecast_id=hashlib.sha256(f"{inventory.get('collected_at', utc_now_iso())}:{current_level}".encode("utf-8")).hexdigest()[:16],
            generated_at=utc_now_iso(),
            level=current_level,
            summary=summary,
            state_text=state_text,
            why_no_cards=why_no_cards,
            last_error=", ".join(catalog.get("errors", [])),
            affected_products=affected_products,
            cve_count=sum(len(card.get("cves", [])) for card in cards),
            kev_count=sum(len(card.get("kev_cves", [])) for card in cards),
            highest_severity=highest_severity,
            recommended_action=self._recommended_action(current_level, cards, inventory),
            cards=cards,
            previous_level=previous_level,
            next_check_at=(datetime.now(timezone.utc) + timedelta(seconds=self.update_interval_seconds)).isoformat(),
            source_age_hours=0,
            cache_age_text="fresh" if not catalog.get("errors") else "degraded",
            should_announce=should_announce,
            sources_used=catalog.get("data_sources_used", []),
            inventory=inventory,
            catalog_update_status=catalog.get("catalog_update_status", "updated"),
            errors=catalog.get("errors", []),
            simulated=False,
            source_mode="live",
            apple_source_status=self._source_status(catalog).get("apple", ""),
            kev_source_status=self._source_status(catalog).get("kev", ""),
            nvd_source_status=self._source_status(catalog).get("nvd", ""),
            epss_source_status=self._source_status(catalog).get("epss", ""),
            filtered_non_apple_cves_count=int(catalog.get("cves_evaluated", len(catalog.get("cves", [])))) - len(cards),
            hidden_review_needed_count=sum(1 for card in cards if str(card.get("applicability", "")) == "review_needed"),
            last_successful_update_at=utc_now_iso() if not catalog.get("errors") else "",
            card_count=len(cards),
            diagnostics=self._last_diagnostics,
        )
        LOGGER.info("Apple Security Forecast built forecast_id=%s level=%s cards=%d announce=%s", forecast.forecast_id, forecast.level, len(cards), forecast.should_announce)
        return forecast

    def purge_simulated_forecasts(self) -> None:
        rows = self.db.list_apple_security_forecast_cards(limit=500)
        demo_forecast_ids = {str(item.get("forecast_id", "")) for item in rows if bool(item.get("simulated", False))}
        demo_forecast_ids.update(
            {
                str(item.get("forecast_id", ""))
                for item in self.db.list_apple_security_forecast_cards(limit=500)
                if str(item.get("source_mode", "")) == "demo"
            }
        )
        demo_forecasts = [item for item in self.db.conn.execute("SELECT forecast_id FROM apple_security_forecasts").fetchall() if str(item["forecast_id"]).startswith("demo")]
        for item in demo_forecasts:
            demo_forecast_ids.add(str(item["forecast_id"]))
        for forecast_id in sorted(filter(None, demo_forecast_ids)):
            self.db.delete_apple_security_forecast(forecast_id)

    def diagnostics_snapshot(self) -> dict[str, Any]:
        latest_forecast = self.db.latest_apple_security_forecast() or {}
        latest_payload = latest_forecast.get("payload_json", {})
        latest_cards = self.db.list_apple_security_forecast_cards(limit=500)
        latest_review = self.db.latest_apple_security_review_state()
        legacy_cache = self.db.latest_cve_radar_cache() or {}
        legacy_payload = legacy_cache.get("payload_json", {})
        inventory = latest_payload.get("inventory", {}) or (legacy_payload.get("inventory", {}) if legacy_payload else {})
        apple_status = "updated" if "Apple security releases" in latest_payload.get("sources_used", []) else "cache"
        kev_status = "updated" if "CISA KEV" in latest_payload.get("sources_used", []) else "cache"
        epss_status = "updated" if "FIRST EPSS" in latest_payload.get("sources_used", []) else "cache"
        nvd_status = "updated" if "NVD CVE API" in latest_payload.get("sources_used", []) else "cache"
        return {
            "last_update_time": latest_forecast.get("generated_at", "") or legacy_cache.get("updated_at", ""),
            "last_successful_update_time": latest_payload.get("last_successful_update_at", latest_forecast.get("generated_at", "")),
            "cache_age": latest_payload.get("cache_age_text", "unknown"),
            "apple_source_status": latest_payload.get("apple_source_status", apple_status),
            "kev_source_status": latest_payload.get("kev_source_status", kev_status),
            "nvd_source_status": latest_payload.get("nvd_source_status", nvd_status),
            "epss_source_status": latest_payload.get("epss_source_status", epss_status),
            "inventory": {
                "macos_version": inventory.get("macos_version", ""),
                "macos_build": inventory.get("macos_build", ""),
                "safari_version": inventory.get("safari_version", ""),
                "safari_build": inventory.get("safari_build", ""),
                "safari_detection_method": inventory.get("safari_detection_method", ""),
                "webkit_version": inventory.get("webkit_version", ""),
                "xcode_version": inventory.get("xcode_version", ""),
                "command_line_tools_version": inventory.get("command_line_tools_version", ""),
                "architecture": inventory.get("architecture", ""),
                "device_model": inventory.get("device_model", ""),
                "software_update_check_status": inventory.get("software_update_check_status", ""),
                "software_update_error": inventory.get("software_update_error", ""),
                "privacy_guarantee": inventory.get("privacy_guarantee", ""),
            },
            "cards_generated_count": len(latest_cards),
            "advisories_downloaded": int(latest_payload.get("diagnostics", {}).get("advisories_downloaded", 0)),
            "advisories_parsed": int(latest_payload.get("diagnostics", {}).get("advisories_parsed", 0)),
            "advisories_within_90_days": int(latest_payload.get("diagnostics", {}).get("advisories_within_90_days", 0)),
            "invalid_advisories": int(latest_payload.get("diagnostics", {}).get("invalid_advisories", 0)),
            "filtered_advisories": int(latest_payload.get("diagnostics", {}).get("filtered_advisories", 0)),
            "historical_advisories": int(latest_payload.get("diagnostics", {}).get("historical_advisories", 0)),
            "stale_advisories": int(latest_payload.get("diagnostics", {}).get("stale_advisories", 0)),
            "non_mac_advisories_hidden": int(latest_payload.get("diagnostics", {}).get("non_mac_advisories_hidden", 0)),
            "review_needed_hidden": int(latest_payload.get("diagnostics", {}).get("review_needed_hidden", 0)),
            "applicable_advisories": int(latest_payload.get("diagnostics", {}).get("applicable_advisories", 0)),
            "filtered_non_apple_cves_count": int(latest_payload.get("filtered_non_apple_cves_count", 0)),
            "hidden_review_needed_count": int(latest_payload.get("hidden_review_needed_count", 0)),
            "last_error": latest_payload.get("last_error", ""),
            "why_no_cards": latest_payload.get("why_no_cards", ""),
            "table_counts": {
                "apple_security_forecasts": len(self.db.conn.execute("SELECT forecast_id FROM apple_security_forecasts").fetchall()),
                "apple_security_forecast_cards": len(self.db.conn.execute("SELECT card_id FROM apple_security_forecast_cards").fetchall()),
                "apple_security_cve_cache": len(self.db.conn.execute("SELECT cve_id FROM apple_security_cve_cache").fetchall()),
                "apple_security_review_state": len(self.db.conn.execute("SELECT card_id FROM apple_security_review_state").fetchall()),
            },
            "review_state_count": len(latest_review),
            "simulated": bool(latest_payload.get("simulated", False)),
        }

    def mark_reviewed(self, card_id: str, notes: str = "") -> None:
        card = self.db.list_apple_security_forecast_cards(limit=500)
        match = next((item for item in card if item.get("card_id") == card_id), None)
        cve_id = ""
        if match:
            cve_id = str(match.get("cves", [""])[0]) if match.get("cves") else ""
        self.db.record_apple_security_review_state(card_id, cve_id=cve_id, status="reviewed", notes=notes, payload=match or {})

    def snooze(self, card_id: str, *, days: int | None = None, until_next_version_change: bool = False, notes: str = "") -> None:
        card = self.db.list_apple_security_forecast_cards(limit=500)
        match = next((item for item in card if item.get("card_id") == card_id), None)
        cve_id = ""
        version_marker = str(match.get("detected_version", "")) if match else ""
        snooze_until = ""
        snooze_scope = ""
        if days is not None:
            snooze_until = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            snooze_scope = "time"
        elif until_next_version_change:
            snooze_scope = "next_version_change"
        self.db.record_apple_security_review_state(
            card_id,
            cve_id=cve_id,
            status="snoozed",
            snooze_until=snooze_until,
            snooze_scope=snooze_scope,
            version_marker=version_marker,
            notes=notes,
            payload=match or {},
        )

    def _catalog(self, *, manual: bool = False, force: bool = False) -> dict[str, Any]:
        try:
            catalog = self.updater.update_catalog()
        except Exception:
            cached = self.db.latest_cve_radar_cache()
            if cached:
                payload = dict(cached.get("payload_json", {}))
                payload["catalog_update_status"] = "offline-cache"
                return payload
            return {
                "timestamp": utc_now_iso(),
                "data_sources_used": [],
                "kev": {},
                "epss": {},
                "cves": [],
                "apple_security_releases": [],
                "catalog_update_status": "offline-rules",
                "errors": ["CVE catalog update failed and no cache was available."],
            }
        self.db.record_cve_radar_cache(catalog, source=str(catalog.get("catalog_update_status", "catalog")), updated_at=str(catalog.get("timestamp", utc_now_iso())))
        return catalog

    def _build_cards(self, catalog: dict[str, Any], inventory: dict[str, Any], current_scan_result: ScanResult | None) -> list[AppleSecurityForecastCard]:
        cards: dict[str, AppleSecurityForecastCard] = {}
        products = inventory.get("products", [])
        diagnostics = {
            "advisories_downloaded": len(catalog.get("cves", [])),
            "advisories_parsed": 0,
            "advisories_within_90_days": 0,
            "invalid_advisories": 0,
            "filtered_advisories": 0,
            "historical_advisories": 0,
            "stale_advisories": 0,
            "ecosystem_advisories": 0,
            "non_mac_advisories_hidden": 0,
            "review_needed_hidden": 0,
            "applicable_advisories": 0,
            "active_forecast_cards": 0,
        }
        for item in catalog.get("cves", []):
            filter_reason = self._active_apple_advisory_filter_reason(item)
            if filter_reason:
                if filter_reason in {"invalid-date", "future-date", "pre-2020", "missing-date"}:
                    diagnostics["invalid_advisories"] += 1
                elif filter_reason == "historical":
                    diagnostics["historical_advisories"] += 1
                    diagnostics["stale_advisories"] += 1
                elif filter_reason == "ecosystem-only":
                    diagnostics["ecosystem_advisories"] += 1
                    diagnostics["non_mac_advisories_hidden"] += 1
                elif filter_reason == "unsupported-family":
                    diagnostics["non_mac_advisories_hidden"] += 1
                else:
                    diagnostics["filtered_advisories"] += 1
                continue
            diagnostics["advisories_parsed"] += 1
            advisory_dt = _advisory_dt(item)
            if advisory_dt and (datetime.now(timezone.utc) - advisory_dt).days <= APPLE_FORECAST_DEFAULT_ACTIVE_DAYS:
                diagnostics["advisories_within_90_days"] += 1
            match = self._match_apple_item(item, products, inventory, catalog.get("kev", {}))
            if match["applicability"] == "not_applicable":
                diagnostics["filtered_advisories"] += 1
                continue
            if match["applicability"] == "review_needed" and not getattr(self.config, "show_review_needed_apple_cves", False):
                diagnostics["review_needed_hidden"] += 1
                continue
            diagnostics["applicable_advisories"] += 1
            card_key = match["category"]
            card = cards.get(card_key)
            if card is None:
                card = AppleSecurityForecastCard(
                    card_id=hashlib.sha256(card_key.encode("utf-8")).hexdigest()[:16],
                    forecast_id="",
                    title=match["title"],
                    category=match["category"],
                    forecast_level="clear",
                    affected_local_product=match["affected_local_product"],
                    detected_version=match["detected_version"],
                    fixed_version=match.get("fixed_version", ""),
                    cves=[],
                    kev_cves=[],
                    epss_high_cves=[],
                    applicability=match["applicability"],
                    confidence=match["confidence"],
                    why_shown=match["why_shown"],
                    what_to_do=match["what_to_do"],
                    update_path=match["update_path"],
                    references=[],
                    status="new",
                    snooze_until="",
                    summary=match["title"],
                    affected_products=[],
                    highest_severity="info",
                    source="apple",
                )
                self._apply_risk_context(card, known_exploited=False, patch_available=bool(match.get("fixed_version")), confidence_reason=match.get("confidence_reason", ""))
                self._apply_false_positive_review(card, item, match, catalog)
                cards[card_key] = card
            cve_id = str(item.get("cve_id", ""))
            card.cves.append(cve_id)
            if cve_id in catalog.get("kev", {}):
                card.kev_cves.append(cve_id)
            epss = catalog.get("epss", {}).get(cve_id, {})
            if float(epss.get("percentile", 0.0)) >= 0.90:
                card.epss_high_cves.append(cve_id)
            card.references = sorted({*card.references, *(item.get("references", [])), APPLE_SECURITY_RELEASES_URL, f"{NVD_CVE_API_URL}?cveId={cve_id}"} - {""})
            card.affected_products = sorted({*card.affected_products, match["affected_local_product"]})
            card.cve_count = len(set(card.cves))
            card.kev_count = len(set(card.kev_cves))
            card.highest_severity = _severity_max(card.highest_severity, _severity_from_cvss(item.get("cvss_score")))
            if cve_id in catalog.get("kev", {}):
                if card.applicability == "confirmed_applicable" and match.get("fixed_version"):
                    card.forecast_level = _forecast_level_max(card.forecast_level, "critical")
                else:
                    card.forecast_level = _forecast_level_max(card.forecast_level, "urgent")
            elif float(epss.get("percentile", 0.0)) >= 0.90:
                card.forecast_level = _forecast_level_max(card.forecast_level, "elevated")
            elif card.applicability in {"confirmed_applicable", "likely_applicable"}:
                card.forecast_level = _forecast_level_max(card.forecast_level, APPLE_FORECAST_LEVEL_FOR_SEVERITY[card.highest_severity])
            self._apply_risk_context(
                card,
                known_exploited=bool(card.kev_cves),
                patch_available=bool(match.get("fixed_version")),
                confidence_reason=match.get("confidence_reason", ""),
            )
            self._apply_false_positive_review(card, item, match, catalog)
            if current_scan_result is not None:
                card.why_shown = self._augment_why_shown(card.why_shown, current_scan_result, match["affected_local_product"])
            self.db.record_apple_security_cve_cache(cve_id, item, source="apple-security-releases")
        if inventory.get("software_update_available"):
            card_key = "apple-security-update-available"
            update_card = cards.get(card_key)
            if update_card is None:
                update_card = AppleSecurityForecastCard(
                    card_id=hashlib.sha256(card_key.encode("utf-8")).hexdigest()[:16],
                    forecast_id="",
                    title="Apple Security Update Available",
                    category="macOS",
                    forecast_level="elevated",
                    affected_local_product="macOS",
                    detected_version=str(inventory.get("macos_version", "")),
                    fixed_version="",
                    cves=[],
                    kev_cves=[],
                    epss_high_cves=[],
                    applicability="likely_applicable",
                    confidence="medium",
                    why_shown="Software Update reports pending Apple updates.",
                    what_to_do="Review Software Update and apply supported Apple security updates.",
                    update_path="System Settings > General > Software Update",
                    references=[APPLE_SECURITY_RELEASES_URL],
                    status="new",
                    snooze_until="",
                    summary="Apple Security Update Available",
                    affected_products=["macOS"],
                    highest_severity="high",
                    source="apple",
                )
                cards[card_key] = update_card
                self._apply_risk_context(update_card, known_exploited=False, patch_available=True, confidence_reason="Software Update reports pending Apple updates.")
                update_card.false_positive_review = {
                    "result": "Low false-positive risk",
                    "reason": "macOS Software Update reported pending Apple updates locally.",
                    "checks": {
                        "local_update_signal": True,
                        "private_data_inspected": False,
                    },
                }
                update_card.planning_guidance = self._planning_guidance(update_card)
                update_card.forecast_phrase = self._forecast_phrase(update_card)
            update_card.forecast_level = _forecast_level_max(update_card.forecast_level, "elevated")
        grouped = list(cards.values())
        diagnostics["active_forecast_cards"] = len(grouped)
        self._last_diagnostics = diagnostics
        return grouped

    def _active_apple_advisory_filter_reason(self, item: dict[str, Any]) -> str:
        if not self._apple_related(item):
            return "non-apple"
        if not self._has_apple_release_evidence(item):
            return "no-apple-release-evidence"
        family = self._primary_family(item)
        if family in APPLE_ECOSYSTEM_ONLY_KEYS and not getattr(self.config, "include_apple_ecosystem_advisories", False):
            return "ecosystem-only"
        if family not in APPLE_MAC_FOCUSED_FAMILY_KEYS:
            return "unsupported-family"
        advisory_dt = _advisory_dt(item)
        if advisory_dt is None:
            return "missing-date"
        now = datetime.now(timezone.utc)
        if advisory_dt > now + timedelta(days=1):
            return "future-date"
        if advisory_dt.year < APPLE_FORECAST_MIN_YEAR:
            return "pre-2020"
        if (now - advisory_dt).days > APPLE_FORECAST_MAX_ACTIVE_DAYS:
            return "historical"
        return ""

    def _has_apple_release_evidence(self, item: dict[str, Any]) -> bool:
        references = " ".join(str(ref) for ref in item.get("references", []))
        text = f"{references} {item.get('description', '')}".lower()
        return "support.apple.com" in text or "apple security" in text or "https://support.apple.com/en-us/100100" in text

    def _primary_family(self, item: dict[str, Any]) -> str:
        for affected in item.get("affected_products", []):
            family = normalize_product_name(affected.get("product", ""))
            if family:
                return family
        text = f"{item.get('description', '')} {' '.join(item.get('references', []))}".lower()
        for family in ["visionos", "watchos", "tvos", "ipados", "ios", "macos", "safari", "webkit", "xcode"]:
            if family in text:
                return family
        return ""

    def _apply_risk_context(self, card: AppleSecurityForecastCard, *, known_exploited: bool, patch_available: bool, confidence_reason: str) -> None:
        likelihood = "High" if known_exploited else "Medium" if card.forecast_level in {"elevated", "urgent", "critical"} else "Low"
        impact = "High" if card.highest_severity in {"critical", "high"} else "Medium" if card.highest_severity == "medium" else "Low"
        exposure = "Confirmed" if card.applicability == "confirmed_applicable" else "Likely" if card.applicability == "likely_applicable" else "Review Needed"
        card.confidence_reason = confidence_reason or "Apple advisory and local product family were correlated."
        card.risk_factors = {
            "likelihood": likelihood,
            "impact": impact,
            "exposure": exposure,
            "exploit_availability": "Known exploited" if known_exploited else "Not confirmed",
            "known_exploitation": "Yes" if known_exploited else "No",
            "patch_availability": "Yes" if patch_available else "Unknown",
            "overall": card.forecast_level.title(),
        }
        card.supporting_evidence = [
            f"Local product: {card.affected_local_product} {card.detected_version}".strip(),
            f"Recommended version/fix: {card.fixed_version or 'review Apple advisory'}",
            f"Confidence: {card.confidence}",
            card.confidence_reason,
        ]

    def _apply_false_positive_review(
        self,
        card: AppleSecurityForecastCard,
        item: dict[str, Any],
        match: dict[str, Any],
        catalog: dict[str, Any],
    ) -> None:
        detected_version = _parse_version(str(card.detected_version)) or str(card.detected_version)
        version_check = _version_is_older(detected_version, str(card.fixed_version))
        checks = {
            "apple_release_evidence": self._has_apple_release_evidence(item),
            "mac_relevant_product": self._primary_family(item) in APPLE_MAC_FOCUSED_FAMILY_KEYS,
            "local_product_detected": bool(card.affected_local_product and card.detected_version),
            "fixed_version_available": bool(card.fixed_version),
            "version_confirms_exposure": version_check is True,
            "version_confirms_not_affected": version_check is False,
            "kev_family_match": bool(card.cves and any(cve_id in catalog.get("kev", {}) for cve_id in card.cves)),
            "active_advisory_window": not self._active_apple_advisory_filter_reason(item),
            "private_data_inspected": False,
        }
        if checks["version_confirms_not_affected"]:
            result = "Likely not affected"
            reason = "The detected local version appears to be at or newer than the Apple fixed version."
        elif card.applicability == "confirmed_applicable" and checks["apple_release_evidence"] and checks["local_product_detected"]:
            result = "Low false-positive risk"
            reason = "Apple release evidence, local product detection, and version comparison all point to this Mac."
        elif card.applicability == "likely_applicable":
            result = "Moderate false-positive risk"
            reason = "The product family matches, but exact version mapping is incomplete. Verify Software Update before treating this as urgent."
        else:
            result = "Review before acting"
            reason = "The advisory is Apple-related, but local applicability is not strong enough for an immediate action recommendation."
        card.false_positive_review = {
            "result": result,
            "reason": reason,
            "checks": checks,
        }
        card.planning_guidance = self._planning_guidance(card)
        card.forecast_phrase = self._forecast_phrase(card)

    def _forecast_phrase(self, card: AppleSecurityForecastCard) -> str:
        if card.forecast_level == "critical":
            return "Update likely needed today"
        if card.forecast_level == "urgent":
            return "Plan an update soon"
        if card.forecast_level == "elevated":
            return "Check Software Update today"
        if card.forecast_level == "watch":
            return "Watch and verify"
        return "No update planning needed"

    def _planning_guidance(self, card: AppleSecurityForecastCard) -> str:
        review = getattr(card, "false_positive_review", {}) or {}
        result = str(review.get("result", ""))
        if result == "Likely not affected":
            return "No action is planned from this card unless Software Update or Apple guidance changes."
        if card.forecast_level == "critical":
            return "Plan to update today after confirming the update appears in Software Update or Apple release notes."
        if card.forecast_level == "urgent":
            return "Plan time to update soon. Verify the Apple advisory and local version before escalating concern."
        if card.forecast_level == "elevated":
            return "Check Software Update today or during the next normal maintenance window."
        if card.forecast_level == "watch":
            return "No immediate action. Keep this on the radar until Apple or local version evidence becomes clearer."
        return "No Apple security update planning is needed from this forecast card."

    def _augment_why_shown(self, base: str, current_scan_result: ScanResult, product: str) -> str:
        if not current_scan_result:
            return base
        open_ports = {
            int(item.get("port") if isinstance(item, dict) else getattr(item, "port", 0))
            for item in current_scan_result.artifacts.get("ports", {}).get("listening", [])
            if (item.get("port") if isinstance(item, dict) else getattr(item, "port", None)) is not None
        }
        if open_ports.intersection({2375, 5432, 3306, 27017, 6379, 9200, 8000, 8080, 8888}):
            return f"{base} Local service exposure was detected on this Mac, so the forecast matters more if the affected Apple software is used for web, build, or update workflows."
        return base

    def _match_apple_item(
        self,
        item: dict[str, Any],
        products: list[dict[str, Any]],
        inventory: dict[str, Any],
        kev_map: dict[str, Any],
    ) -> dict[str, Any]:
        affected_products = item.get("affected_products", [])
        cve_id = str(item.get("cve_id", ""))
        product_name = str(affected_products[0].get("product", "")) if affected_products else ""
        family = normalize_product_name(product_name)
        fixed_version = ""
        if affected_products:
            fixed_version = str(affected_products[0].get("versionEndExcluding", "")) or str(affected_products[0].get("versionEndIncluding", ""))
        detected_product = ""
        detected_version = ""
        confidence = "review-needed"
        applicability = "review_needed"
        title = "Review Needed: Apple-related CVE may affect this OS family"
        category = "Apple App"
        why_shown = "Apple product family match detected."
        what_to_do = "Review Software Update and Apple advisories for this product family."
        update_path = "System Settings > General > Software Update"
        if family in {"macos", "osx"}:
            category = "macOS"
            detected_product = "macOS"
            detected_version = f"{inventory.get('macos_version', '')} ({inventory.get('macos_build', '')})".strip()
            if detected_version.strip():
                confidence = "high"
                version_is_older = _version_is_older(inventory.get("macos_version", ""), fixed_version)
                if version_is_older is True:
                    applicability = "confirmed_applicable"
                    title = "Apple Security Update Available"
                    why_shown = "Detected macOS build matches an Apple security advisory family."
                    what_to_do = "Review Software Update and install the applicable macOS security update."
                elif version_is_older is False and fixed_version:
                    applicability = "not_applicable"
                else:
                    applicability = "likely_applicable"
            else:
                applicability = "review_needed"
        elif family in {"safari", "webkit"}:
            category = "Safari/WebKit"
            detected_product = "Safari"
            detected_version = inventory.get("safari_version", "") or inventory.get("webkit_version", "")
            if detected_version:
                confidence = "high"
                version_is_older = _version_is_older(detected_version, fixed_version)
                if version_is_older is True:
                    applicability = "confirmed_applicable"
                    title = "Safari/WebKit Security Update"
                    why_shown = "Detected Safari/WebKit version matches an Apple advisory family."
                    what_to_do = "Review Software Update and install the Safari/WebKit security update."
                elif version_is_older is False and fixed_version:
                    applicability = "not_applicable"
                else:
                    applicability = "likely_applicable"
            else:
                applicability = "review_needed"
        elif family in {"xcode", "commandlinetools"}:
            category = "Xcode/Developer Tools"
            detected_product = "Xcode"
            detected_version = inventory.get("xcode_version", "") or inventory.get("command_line_tools_version", "")
            if detected_version:
                confidence = "high"
                version_is_older = _version_is_older(detected_version, fixed_version)
                if version_is_older is True:
                    applicability = "confirmed_applicable"
                    title = "Xcode / Developer Tools Security Update"
                    why_shown = "Detected Xcode or Command Line Tools version matches an Apple advisory family."
                    what_to_do = "Review App Store updates or Apple developer downloads for Xcode security fixes."
                    update_path = "App Store > Updates or developer.apple.com downloads"
                elif version_is_older is False and fixed_version:
                    applicability = "not_applicable"
                else:
                    applicability = "likely_applicable"
            else:
                applicability = "review_needed"
        else:
            category = "Apple App"
            detected_product = product_name or "Apple app"
            detected_version = ""
            applicability = "review_needed"
        if cve_id in kev_map:
            if applicability not in {"not_applicable"}:
                applicability = "confirmed_applicable" if applicability != "review_needed" else "review_needed"
            title = "Known Exploited Apple Vulnerability"
            why_shown = "CISA KEV includes this Apple-related CVE and the local Apple family matches."
        if confidence == "high":
            confidence_reason = "Apple advisory references the installed product family and the local version was detected."
        elif confidence == "medium":
            confidence_reason = "Apple advisory references the installed product family, but exact version mapping is incomplete."
        else:
            confidence_reason = "Product family matched, but local version or Apple fixed-version data is incomplete."
        return {
            "cve_id": cve_id,
            "title": title,
            "category": category,
            "affected_local_product": detected_product,
            "detected_version": detected_version,
            "fixed_version": fixed_version,
            "applicability": applicability,
            "confidence": confidence,
            "why_shown": why_shown,
            "what_to_do": what_to_do,
            "update_path": update_path,
            "highest_severity": _severity_from_cvss(item.get("cvss_score")),
            "source": "apple",
            "references": list(item.get("references", [])),
            "confidence_reason": confidence_reason,
        }

    def _apple_related(self, item: dict[str, Any]) -> bool:
        text = f"{item.get('description', '')} {' '.join(item.get('references', []))}".lower()
        if "apple" in text or "macos" in text or "safari" in text or "webkit" in text or "xcode" in text:
            return True
        for affected in item.get("affected_products", []):
            if normalize_product_name(affected.get("product", "")) in APPLE_SECURITY_FAMILY_KEYS:
                return True
        return False

    def _forecast_level(self, cards: list[dict[str, Any]], inventory: dict[str, Any]) -> str:
        if not cards:
            return "clear"
        if any(card.get("forecast_level") == "critical" for card in cards):
            return "critical"
        if any(card.get("forecast_level") == "urgent" for card in cards):
            return "urgent"
        if any(card.get("forecast_level") == "elevated" for card in cards):
            return "elevated"
        if any(card.get("applicability") == "review_needed" for card in cards):
            return "watch"
        if inventory.get("software_update_available"):
            return "elevated"
        return "watch"

    def _summary_text(self, level: str, cards: list[dict[str, Any]], inventory: dict[str, Any]) -> str:
        if level == "clear":
            return "No relevant Apple security updates or high-confidence Apple CVEs were identified."
        if level == "critical":
            return "A known-exploited Apple security issue appears confirmed for this Mac and a security update is available."
        if level == "urgent":
            return "Known-exploited or critical Apple security items likely apply to this Mac."
        if level == "elevated":
            return "Apple security update may apply to macOS, Safari, WebKit, or Xcode on this Mac."
        return "Apple-related items exist, but version mapping is incomplete. Review update availability."

    def _recommended_action(self, level: str, cards: list[dict[str, Any]], inventory: dict[str, Any]) -> str:
        if not cards:
            return "No immediate Apple update action required."
        if any(card.get("category") == "Xcode/Developer Tools" for card in cards):
            return "Review App Store updates or Apple developer downloads for Xcode and Command Line Tools."
        return "Open System Settings > General > Software Update and review Apple's release notes."

    def _apply_review_state(self, cards: list[AppleSecurityForecastCard]) -> list[AppleSecurityForecastCard]:
        state = {item.get("card_id"): item for item in self.db.latest_apple_security_review_state()}
        current_cards: list[AppleSecurityForecastCard] = []
        for card in cards:
            review = state.get(card.card_id, {})
            if review:
                card.status = str(review.get("status", card.status))
                card.snooze_until = str(review.get("snooze_until", card.snooze_until))
                if card.status in {"reviewed", "snoozed"} and card.snooze_until:
                    # keep in history, but display only when explicitly filtered
                    pass
            current_cards.append(card)
        return current_cards


group_alerts_for_display = group_forecast_cards_for_display
CveRadarAlert = AppleSecurityForecastCard
CveRadarEngine = AppleSecurityForecastEngine

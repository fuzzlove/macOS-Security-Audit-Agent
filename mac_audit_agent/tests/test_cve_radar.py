from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.cve_radar import CveRadarEngine, collect_apple_security_inventory, group_forecast_cards_for_display
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.cve_radar_panel import CveRadarPanel


def make_engine(tmp_path: Path) -> CveRadarEngine:
    config = AuditConfig(logs_dir=tmp_path / "logs", cache_dir=tmp_path / "cache")
    db = AuditDatabase(tmp_path / "audit.sqlite", config.logs_dir)
    return CveRadarEngine(db, config)


def make_inventory(*products: tuple[str, str]) -> dict:
    return {
        "collected_at": "2026-06-01T00:00:00+00:00",
        "platform": "macOS-14.0",
        "macos_version": "14.0",
        "macos_build": "23A344",
        "safari_version": "17.0",
        "webkit_version": "17.0",
        "xcode_version": "15.0",
        "command_line_tools_version": "15.0",
        "software_update_available": False,
        "software_update_items": [],
        "products": [
            {
                "product": product,
                "normalized_product": "".join(ch.lower() for ch in product if ch.isalnum()),
                "version": version,
                "source": "test",
                "vendor": "apple",
                "family": "".join(ch.lower() for ch in product if ch.isalnum()),
                "path": "",
                "notes": "",
            }
            for product, version in products
        ],
        "summary": {"product_count": len(products), "apple_app_count": 0, "software_update_available": False},
    }


def make_apple_cve(
    cve_id: str,
    product: str,
    *,
    cvss: float,
    fixed_version: str,
    title: str | None = None,
    references: list[str] | None = None,
) -> dict:
    return {
        "cve_id": cve_id,
        "description": f"{product} issue",
        "cvss_score": cvss,
        "published_date": "2026-05-01T00:00:00Z",
        "last_modified_date": "2026-05-02T00:00:00Z",
        "affected_products": [
            {
                "product": product,
                "vendor": "apple",
                "versionEndExcluding": fixed_version,
            }
        ],
        "references": references if references is not None else ["https://support.apple.com/en-us/100100"],
        "title": title or cve_id,
    }


def _forecast_cards(alerts: list[dict]) -> list[dict]:
    return group_forecast_cards_for_display(alerts)


def test_kev_apple_cve_ranks_highest(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {
        "kev": {"CVE-APPLE-1": {"cveID": "CVE-APPLE-1"}},
        "epss": {},
        "cves": [
            make_apple_cve("CVE-APPLE-1", "macOS", cvss=9.8, fixed_version="14.1"),
            make_apple_cve("CVE-APPLE-2", "Safari", cvss=8.0, fixed_version="17.1"),
        ],
    }
    alerts = engine._build_cards(catalog, make_inventory(("macOS", "14.0"), ("Safari", "17.0")), None)
    cards = _forecast_cards([item.to_dict() for item in alerts])
    assert cards[0]["kev_cves"]
    assert cards[0]["forecast_level"] == "urgent"


def test_high_epss_ranks_higher_than_low_epss(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {
        "kev": {},
        "epss": {
            "CVE-APPLE-1": {"score": 0.9, "percentile": 0.99},
            "CVE-APPLE-2": {"score": 0.1, "percentile": 0.10},
        },
        "cves": [
            make_apple_cve("CVE-APPLE-1", "Safari", cvss=7.0, fixed_version="17.1"),
            make_apple_cve("CVE-APPLE-2", "Xcode", cvss=7.0, fixed_version="15.1"),
        ],
    }
    alerts = engine._build_cards(catalog, make_inventory(("Safari", "17.0"), ("Xcode", "15.0")), None)
    cards = _forecast_cards([item.to_dict() for item in alerts])
    assert cards[0]["epss_high_cves"]


def test_exact_product_version_match_gives_high_confidence(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {"kev": {}, "epss": {}, "cves": [make_apple_cve("CVE-APPLE-1", "macOS", cvss=7.0, fixed_version="14.1")]}
    alerts = engine._build_cards(catalog, make_inventory(("macOS", "14.0")), None)
    assert alerts[0].confidence == "high"
    assert alerts[0].applicability == "confirmed_applicable"


def test_product_match_without_version_is_review_needed(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {"kev": {}, "epss": {}, "cves": [make_apple_cve("CVE-APPLE-1", "Safari", cvss=7.0, fixed_version="17.1")]}
    inventory = make_inventory(("Safari", ""))
    inventory["products"][0]["version"] = ""
    inventory["safari_version"] = ""
    inventory["webkit_version"] = ""
    alerts = engine._build_cards(catalog, inventory, None)
    assert alerts[0].applicability == "review_needed"


def test_unrelated_cve_is_not_alerted(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {"kev": {}, "epss": {}, "cves": [make_apple_cve("CVE-APPLE-1", "Windows", cvss=9.8, fixed_version="1.0", references=[])]}
    alerts = engine._build_cards(catalog, make_inventory(("macOS", "14.0")), None)
    assert alerts == []


def test_apple_cves_group_into_apple_security_update_card(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {
        "kev": {},
        "epss": {},
        "cves": [
            make_apple_cve("CVE-APPLE-1", "Safari", cvss=7.5, fixed_version="17.1", title="Safari/WebKit"),
            make_apple_cve("CVE-APPLE-2", "WebKit", cvss=8.0, fixed_version="17.1", title="Safari/WebKit"),
        ],
    }
    alerts = engine._build_cards(catalog, make_inventory(("Safari", "17.0"), ("WebKit", "17.0")), None)
    cards = _forecast_cards([item.to_dict() for item in alerts])
    safari_cards = [item for item in cards if item.get("category") == "Safari/WebKit"]
    assert len(safari_cards) == 1
    assert len(safari_cards[0]["cve_ids"]) == 2


def test_forecast_level_increase_triggers_one_alert(tmp_path: Path, monkeypatch) -> None:
    engine = make_engine(tmp_path)
    engine.db.record_apple_security_forecast(
        {
            "forecast_id": "prev",
            "generated_at": "2026-06-01T00:00:00+00:00",
            "level": "watch",
            "summary": "",
            "affected_products": [],
            "cve_count": 0,
            "kev_count": 0,
            "highest_severity": "info",
            "recommended_action": "",
            "previous_level": "clear",
            "next_check_at": "",
            "payload_json": {"level": "watch"},
        }
    )
    monkeypatch.setattr(
        engine.updater,
        "update_catalog",
        lambda: {
            "timestamp": "2026-06-01T00:00:00+00:00",
            "data_sources_used": ["Apple security releases"],
            "kev": {},
            "epss": {"CVE-APPLE-1": {"score": 0.9, "percentile": 0.99}},
            "cves": [make_apple_cve("CVE-APPLE-1", "Safari", cvss=8.0, fixed_version="17.1")],
            "apple_security_releases": [],
            "catalog_update_status": "updated",
            "errors": [],
        },
    )
    monkeypatch.setattr("mac_audit_agent.cve_radar.collect_apple_security_inventory", lambda: make_inventory(("Safari", "17.0"), ("WebKit", "17.0")))
    forecast = engine.generate_forecast(force=True)
    assert forecast.level == "elevated"
    assert forecast.should_announce is True


def test_same_forecast_level_does_not_realert(tmp_path: Path, monkeypatch) -> None:
    engine = make_engine(tmp_path)
    engine.db.record_apple_security_forecast(
        {
            "forecast_id": "prev",
            "generated_at": "2026-06-01T00:00:00+00:00",
            "level": "elevated",
            "summary": "",
            "affected_products": [],
            "cve_count": 0,
            "kev_count": 0,
            "highest_severity": "info",
            "recommended_action": "",
            "previous_level": "watch",
            "next_check_at": "",
            "payload_json": {"level": "elevated"},
        }
    )
    monkeypatch.setattr(
        engine.updater,
        "update_catalog",
        lambda: {
            "timestamp": "2026-06-01T00:00:00+00:00",
            "data_sources_used": ["Apple security releases"],
            "kev": {},
            "epss": {"CVE-APPLE-1": {"score": 0.9, "percentile": 0.99}},
            "cves": [make_apple_cve("CVE-APPLE-1", "Safari", cvss=8.0, fixed_version="17.1")],
            "apple_security_releases": [],
            "catalog_update_status": "updated",
            "errors": [],
        },
    )
    monkeypatch.setattr("mac_audit_agent.cve_radar.collect_apple_security_inventory", lambda: make_inventory(("Safari", "17.0"), ("WebKit", "17.0")))
    forecast = engine.generate_forecast(force=True)
    assert forecast.level == "elevated"
    assert forecast.should_announce is False


def test_reviewed_and_snoozed_cves_remain_in_history(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {"kev": {}, "epss": {}, "cves": [make_apple_cve("CVE-APPLE-1", "macOS", cvss=7.0, fixed_version="14.1")]}
    alerts = engine._build_cards(catalog, make_inventory(("macOS", "14.0")), None)
    engine.db.record_apple_security_forecast_cards([alerts[0].to_dict()])
    engine.mark_reviewed(alerts[0].card_id, notes="reviewed")
    engine.snooze(alerts[0].card_id, days=1, notes="snoozed")
    stored = engine.db.latest_apple_security_review_state()
    assert stored
    assert stored[0]["status"] == "snoozed"


def test_review_needed_hidden_by_default(tmp_path: Path) -> None:
    QApplication.instance() or QApplication([])
    panel = CveRadarPanel()
    card = {
        "title": "Review Needed: Apple-related CVE may affect this OS family",
        "alerts": [
            {
                "status": "new",
                "applicability": "review_needed",
                "source": "apple",
                "apple_related": True,
            }
        ],
    }
    assert panel._card_visible(card) is False


def test_offline_mode_uses_cached_catalog(tmp_path: Path, monkeypatch) -> None:
    engine = make_engine(tmp_path)
    cached_catalog = {
        "timestamp": "2026-05-01T00:00:00+00:00",
        "data_sources_used": ["Apple security releases"],
        "kev": {},
        "epss": {},
        "cves": [make_apple_cve("CVE-APPLE-1", "macOS", cvss=7.0, fixed_version="14.1")],
        "apple_security_releases": [],
        "catalog_update_status": "cached",
        "errors": [],
    }
    engine.db.record_cve_radar_cache(cached_catalog, updated_at="2024-01-01T00:00:00+00:00")
    monkeypatch.setattr(engine.updater, "update_catalog", lambda: (_ for _ in ()).throw(RuntimeError("offline")))
    catalog = engine._catalog(manual=False, force=False)
    assert catalog["catalog_update_status"] == "offline-cache"
    assert catalog["cves"][0]["cve_id"] == "CVE-APPLE-1"


def test_radar_state_is_separate_from_background_events(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    catalog = {"kev": {}, "epss": {}, "cves": [make_apple_cve("CVE-APPLE-1", "macOS", cvss=7.0, fixed_version="14.1")]}
    alerts = engine._build_cards(catalog, make_inventory(("macOS", "14.0")), None)
    engine.db.record_apple_security_forecast_cards([alerts[0].to_dict()])
    assert engine.db.recent_background_monitor_events() == []
    assert engine.db.list_apple_security_forecast_cards(limit=10)


def test_corrupt_forecast_payload_does_not_crash(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    engine.db.record_apple_security_forecast(
        {
            "forecast_id": "forecast-1",
            "generated_at": "2026-06-01T00:00:00+00:00",
            "level": "clear",
            "summary": "",
            "affected_products": [],
            "cve_count": 0,
            "kev_count": 0,
            "highest_severity": "info",
            "recommended_action": "",
            "previous_level": "clear",
            "next_check_at": "",
            "payload_json": {"level": "clear"},
        }
    )
    engine.db.conn.execute(
        "UPDATE apple_security_forecasts SET payload_json = ? WHERE forecast_id = ?",
        ("{not valid json", "forecast-1"),
    )
    engine.db.conn.commit()

    cached = engine.load_cached_state()
    assert cached["state_text"] in {"Forecast not checked yet", "Clear — no applicable Apple security updates found"}
    assert cached["last_error"] == ""


def test_apple_security_inventory_never_accesses_safari_private_state_or_history(monkeypatch) -> None:
    commands: list[list[str]] = []
    forbidden = ["History", "Cookies", "Cache", "WebKit/WebsiteData", "Private", "Safari/Databases", "pgrep"]

    def fake_run(command, timeout=5):
        joined = " ".join(command)
        commands.append(command)
        assert not any(token.lower() in joined.lower() for token in forbidden), joined
        if command[:2] == ["/usr/bin/sw_vers", "-productVersion"]:
            return "14.4"
        if command[:2] == ["/usr/bin/sw_vers", "-buildVersion"]:
            return "23E214"
        if command == ["/usr/bin/arch"]:
            return "arm64"
        if command[:3] == ["/usr/sbin/sysctl", "-n", "hw.model"]:
            return "Mac14,2"
        if command[-1] == "CFBundleShortVersionString":
            return "17.4"
        if command[-1] == "CFBundleVersion":
            return "19618.1.15.11.14"
        return ""

    def fake_result(command, timeout=5):
        joined = " ".join(command)
        commands.append(command)
        assert not any(token.lower() in joined.lower() for token in forbidden), joined
        return "No new software available.", True

    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command", fake_run)
    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command_result", fake_result)

    inventory = collect_apple_security_inventory()

    assert inventory["safari_version"] == "17.4"
    assert inventory["safari_detection_method"] == "Info.plist CFBundleShortVersionString via defaults"
    assert all("/Applications/Safari.app/Contents/MacOS/Safari" not in " ".join(command) for command in commands)
    assert all("History" not in " ".join(command) for command in commands)


def test_installed_safari_version_detected_via_info_plist_defaults(monkeypatch) -> None:
    def fake_run(command, timeout=5):
        if command == ["/usr/bin/defaults", "read", "/Applications/Safari.app/Contents/Info", "CFBundleShortVersionString"]:
            return "17.5"
        if command == ["/usr/bin/defaults", "read", "/Applications/Safari.app/Contents/Info", "CFBundleVersion"]:
            return "19618.2"
        if command[:2] == ["/usr/bin/sw_vers", "-productVersion"]:
            return "14.5"
        if command[:2] == ["/usr/bin/sw_vers", "-buildVersion"]:
            return "23F79"
        return ""

    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command", fake_run)
    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command_result", lambda command, timeout=5: ("No new software available.", True))

    inventory = collect_apple_security_inventory()

    assert inventory["safari_version"] == "17.5"
    assert inventory["safari_build"] == "19618.2"
    assert inventory["webkit_version"] == "17.5"


def test_softwareupdate_failure_degrades_gracefully(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command", lambda command, timeout=5: "17.5" if command[-1:] == ["CFBundleShortVersionString"] else "")
    monkeypatch.setattr("mac_audit_agent.cve_radar._run_command_result", lambda command, timeout=5: ("softwareupdate failed", False))

    inventory = collect_apple_security_inventory()

    assert inventory["software_update_check_status"] == "failed"
    assert inventory["software_update_error"] == "softwareupdate failed"


def test_forecast_generation_does_not_require_safari_open_or_non_private_mode(tmp_path: Path, monkeypatch) -> None:
    engine = make_engine(tmp_path)
    monkeypatch.setattr(
        engine.updater,
        "update_catalog",
        lambda: {
            "timestamp": "2026-06-01T00:00:00+00:00",
            "data_sources_used": ["Apple security releases"],
            "kev": {},
            "epss": {},
            "cves": [make_apple_cve("CVE-APPLE-SAFARI", "Safari", cvss=8.0, fixed_version="17.6")],
            "apple_security_releases": [],
            "catalog_update_status": "updated",
            "errors": [],
        },
    )
    monkeypatch.setattr(
        "mac_audit_agent.cve_radar.collect_apple_security_inventory",
        lambda: make_inventory(("Safari", "17.5"), ("WebKit", "17.5")),
    )

    forecast = engine.generate_forecast(force=True)

    assert forecast.level == "elevated"
    assert forecast.cards
    assert forecast.inventory["safari_version"] == "17.0" or forecast.inventory["products"][0]["product"] == "Safari"


def test_no_forecast_state_renders_explanation(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)

    cached = engine.load_cached_state()

    assert cached["state_text"] == "Forecast not checked yet"
    assert cached["why_no_cards"] == "No Apple Security Forecast has been checked yet."


def test_safari_webkit_demo_forecast_renders(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)

    forecast = engine.generate_safari_webkit_demo_forecast()

    assert forecast.simulated is True
    assert forecast.source_mode == "demo-safari-webkit"
    assert len(forecast.cards) == 1
    assert forecast.cards[0].category == "Safari/WebKit"
    assert "Private Browsing state is not inspected" in forecast.cards[0].why_shown

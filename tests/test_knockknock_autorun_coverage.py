from __future__ import annotations

import plistlib
from pathlib import Path

from mac_audit_agent.persistence_intelligence.risk_scoring import score_item
from mac_audit_agent.persistence_intelligence.scanner import (
    ApplicationAutorunPluginScanner,
    DynamicLoaderPersistenceScanner,
    LegacyAutorunScanner,
    ScanContext,
    scanner_registry,
)


def _plist(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(payload))


def test_legacy_autorun_scanner_covers_hooks_emond_and_loadable_bundles(tmp_path: Path) -> None:
    system = tmp_path / "system"
    home = tmp_path / "home"
    _plist(
        system / "Library/Preferences/com.apple.loginwindow.plist",
        {"LoginHook": "/usr/local/bin/on-login", "LogoutHook": "/usr/local/bin/on-logout"},
    )
    startup = system / "etc/rc.server"
    startup.parent.mkdir(parents=True, exist_ok=True)
    startup.write_text("#!/bin/sh\n", encoding="utf-8")
    _plist(
        system / "etc/emond.d/rules/suspicious.plist",
        [{"name": "autorun", "actions": [{"command": "/usr/bin/osascript /tmp/task.scpt"}]}],
    )
    for relative in (
        "Library/DirectoryServices/PlugIns/example.dsplug",
        "Library/Spotlight/example.mdimporter",
        "Library/QuickLook/example.qlgenerator",
    ):
        (system / relative).mkdir(parents=True)

    result = LegacyAutorunScanner().scan(ScanContext(home=home, system_root=system))
    mechanisms = {item.mechanism for item in result.items}

    assert {"login_hook", "logout_hook", "startup_script", "event_rule"} <= mechanisms
    assert {"directory_services_plugin", "spotlight_importer", "quicklook_plugin"} <= mechanisms
    event_rule = next(item for item in result.items if item.mechanism == "event_rule")
    assert event_rule.risk_level in {"HIGH", "CRITICAL"}
    assert "T1546" in event_rule.mitre_techniques


def test_dynamic_loader_scanner_extracts_colon_separated_libraries(tmp_path: Path) -> None:
    system = tmp_path / "system"
    home = tmp_path / "home"
    _plist(
        system / "Library/LaunchDaemons/com.example.inject.plist",
        {
            "Label": "com.example.inject",
            "EnvironmentVariables": {
                "DYLD_INSERT_LIBRARIES": "/tmp/first.dylib:/Library/Example/second.dylib"
            },
        },
    )
    _plist(
        system / "Applications/Example.app/Contents/Info.plist",
        {"CFBundleIdentifier": "com.example.app", "LSEnvironment": {"__XPC_DYLD_INSERT_LIBRARIES": "/tmp/xpc.dylib"}},
    )

    result = DynamicLoaderPersistenceScanner().scan(ScanContext(home=home, system_root=system))

    assert len(result.items) == 3
    assert {item.program for item in result.items} == {"/tmp/first.dylib", "/Library/Example/second.dylib", "/tmp/xpc.dylib"}
    assert all(item.mechanism == "dylib_insert" for item in result.items)
    assert all(item.risk_level in {"HIGH", "CRITICAL"} for item in result.items)


def test_application_autorun_scanner_finds_dock_plugin_and_login_helper(tmp_path: Path) -> None:
    system = tmp_path / "system"
    home = tmp_path / "home"
    app = system / "Applications/Example.app"
    _plist(app / "Contents/Info.plist", {"NSDockTilePlugIn": "ExampleDock.bundle"})
    (app / "Contents/PlugIns/ExampleDock.bundle").mkdir(parents=True)
    (app / "Contents/Library/LoginItems/ExampleHelper.app").mkdir(parents=True)

    result = ApplicationAutorunPluginScanner().scan(ScanContext(home=home, system_root=system))

    assert {item.mechanism for item in result.items} == {"dock_tile_plugin", "embedded_login_helper"}


def test_registry_exposes_new_autorun_scanners_and_empty_target_is_not_cwd() -> None:
    scanner_ids = {scanner.scanner_id for scanner in scanner_registry()}
    assert {"legacy_autoruns", "dynamic_loader_persistence", "application_autorun_plugins"} <= scanner_ids

    from mac_audit_agent.persistence_intelligence.models import PersistenceItem

    item = PersistenceItem.create("quicklook_plugin", "/Library/QuickLook/example.qlgenerator")
    score_item(item)
    assert item.risk_score >= 18

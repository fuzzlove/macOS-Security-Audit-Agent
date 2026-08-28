from __future__ import annotations


MECHANISM_MITRE: dict[str, list[str]] = {
    "launch_agent": ["T1543.001"],
    "launch_daemon": ["T1543.004"],
    "login_item": ["T1547.015"],
    "background_item": ["T1547.015"],
    "cron": ["T1053.003"],
    "periodic": ["T1037"],
    "shell_startup": ["T1037", "T1059"],
    "authorization_plugin": ["T1547"],
    "browser_extension": ["T1176"],
    "native_messaging_host": ["T1176", "T1059"],
    "configuration_profile": ["T1556"],
    "certificate_trust": ["T1553"],
    "system_extension": ["T1543"],
    "network_extension": ["T1543"],
    "privileged_helper": ["T1543.004"],
    "path_hijack": ["T1574.007"],
    "support_directory": ["T1059"],
    "user_group": ["T1136"],
    "tcc_indicator": ["T1562"],
    "login_hook": ["T1037.002"],
    "logout_hook": ["T1037.002"],
    "startup_script": ["T1037"],
    "event_rule": ["T1546"],
    "directory_services_plugin": ["T1546"],
    "spotlight_importer": ["T1546"],
    "quicklook_plugin": ["T1546"],
    "dylib_insert": ["T1574.006"],
    "dock_tile_plugin": ["T1546"],
    "embedded_login_helper": ["T1547.015"],
    "ssh_authorized_key": ["T1098.004"],
    "ssh_configuration": ["T1098"],
    "applescript_persistence": ["T1059.002", "T1546"],
    "application_bundle": ["T1547.015"],
}


def mitre_for_mechanism(mechanism: str) -> list[str]:
    return list(MECHANISM_MITRE.get(mechanism, []))


def nist_for_persistence() -> list[str]:
    return ["NIST CSF Detect", "NIST CSF Identify", "NIST CSF Respond", "NIST 800-53 SI-4", "AU-6", "CM-3", "CM-6"]

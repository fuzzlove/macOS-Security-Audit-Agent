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
}


def mitre_for_mechanism(mechanism: str) -> list[str]:
    return list(MECHANISM_MITRE.get(mechanism, []))


def nist_for_persistence() -> list[str]:
    return ["NIST CSF Detect", "NIST CSF Identify", "NIST CSF Respond", "NIST 800-53 SI-4", "AU-6", "CM-3", "CM-6"]

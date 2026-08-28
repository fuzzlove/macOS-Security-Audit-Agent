from __future__ import annotations

import re

TERMS = (
    "malware", "ransomware", "botnet", "trojan", "spyware", "infostealer", "information stealer",
    "rootkit", "backdoor", "supply chain", "malicious package", "command and control", "c2 infrastructure",
    "persistence", "credential theft", "credential stealing", "endpoint compromise", "nation-state",
    "macos malware", "ios malware", "linux malware", "windows malware", "mobile malware",
    "threat intelligence", "cyber espionage", "cyberespionage",
)
PATTERN = re.compile("|".join(re.escape(term) for term in TERMS), re.I)


def is_malware_relevant(title: str, summary: str, categories: tuple[str, ...]) -> bool:
    return bool(PATTERN.search(" ".join((title, summary, *categories))))

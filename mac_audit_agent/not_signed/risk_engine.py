from __future__ import annotations

from pathlib import Path

from .models import ProcessRecord, SoftwareTrustClassification

RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def score(classification: SoftwareTrustClassification, path: Path, processes: tuple[ProcessRecord, ...], persistent: bool = False) -> tuple[str, tuple[str, ...]]:
    severity = "informational"; reasons: list[str] = []
    if classification == SoftwareTrustClassification.REVOKED: severity, reasons = "critical", ["Gatekeeper or certificate assessment rejected or revoked the executable."]
    elif classification == SoftwareTrustClassification.INVALID: severity, reasons = "high", ["The signature is invalid or bundle contents no longer match its seal."]
    elif classification == SoftwareTrustClassification.UNSIGNED: severity, reasons = "medium", ["No usable code signature was found."]
    elif classification == SoftwareTrustClassification.AD_HOC: severity, reasons = "medium", ["An ad hoc signature does not authenticate a developer identity."]
    elif classification == SoftwareTrustClassification.DEVELOPER_ID_VALID: severity, reasons = "low", ["Valid third-party Developer ID signature; notarization was not confirmed."]
    elif classification == SoftwareTrustClassification.UNKNOWN: severity, reasons = "medium", ["Assessment evidence was incomplete; this is not a malicious classification."]
    unusual = str(path).startswith(("/tmp/", "/private/tmp/", "/var/tmp/")) or "/Downloads/" in str(path) or "/Volumes/" in str(path)
    if unusual and processes: severity = max((severity, "high"), key=RANK.get); reasons.append("A running executable is in a temporary, downloaded, or mounted location.")
    if persistent and classification in {SoftwareTrustClassification.UNSIGNED, SoftwareTrustClassification.AD_HOC, SoftwareTrustClassification.UNKNOWN}: severity = max((severity, "high"), key=RANK.get); reasons.append("The item has an automatic persistence mechanism.")
    if any(p.privileged for p in processes) and classification in {SoftwareTrustClassification.UNSIGNED, SoftwareTrustClassification.INVALID, SoftwareTrustClassification.REVOKED}: severity = "critical"; reasons.append("The affected executable is running with root privileges.")
    return severity, tuple(dict.fromkeys(reasons))

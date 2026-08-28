from __future__ import annotations

import shutil
import subprocess

from mac_audit_agent.rootkit_detection.models import RootkitSuspectFinding, SystemIntegrityPosture, stable_id


SAFE_COMMANDS = {
    "csrutil": "/usr/bin/csrutil",
    "spctl": "/usr/sbin/spctl",
    "fdesetup": "/usr/bin/fdesetup",
    "sw_vers": "/usr/bin/sw_vers",
    "softwareupdate": "/usr/sbin/softwareupdate",
    "nvram": "/usr/sbin/nvram",
    "diskutil": "/usr/sbin/diskutil",
}


def _run(command: list[str], timeout: int = 8) -> tuple[str, str]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        output = (completed.stdout or "").strip()
        error = (completed.stderr or "").strip()
        if completed.returncode != 0 and error:
            return output, f"unavailable: {error}"
        return output, error
    except FileNotFoundError:
        return "", "unavailable: command not found"
    except subprocess.TimeoutExpired:
        return "", "unavailable: command timed out"
    except Exception as exc:
        return "", f"unavailable: {type(exc).__name__}: {exc}"


def parse_csrutil_status(text: str) -> str:
    lowered = text.lower()
    if "disabled" in lowered:
        return "disabled"
    if "enabled" in lowered:
        return "enabled"
    return "unknown"


def parse_authenticated_root_status(text: str) -> str:
    lowered = text.lower()
    if "disabled" in lowered:
        return "disabled"
    if "enabled" in lowered:
        return "enabled"
    if "not available" in lowered or "unrecognized" in lowered:
        return "unavailable"
    return "unknown"


def parse_spctl_status(text: str) -> str:
    lowered = text.lower()
    if "assessments disabled" in lowered:
        return "disabled"
    if "assessments enabled" in lowered:
        return "enabled"
    return "unknown"


def parse_fdesetup_status(text: str) -> str:
    lowered = text.lower()
    if "filevault is on" in lowered:
        return "enabled"
    if "filevault is off" in lowered:
        return "disabled"
    return "unknown"


def parse_boot_args(text: str) -> tuple[str, bool]:
    if "not found" in text.lower():
        return "", False
    value = text.strip()
    risky_markers = ("amfi_get_out_of_my_way", "kext-dev-mode", "rootless=0", "keepsyms=1", "debug=")
    return value, any(marker in value for marker in risky_markers)


def collect_system_integrity_posture() -> tuple[SystemIntegrityPosture, list[str]]:
    posture = SystemIntegrityPosture()
    commands: list[str] = []

    if shutil.which("csrutil"):
        commands.append("csrutil status")
        output, error = _run([SAFE_COMMANDS["csrutil"], "status"])
        posture.csrutil_output = output or error
        posture.sip_status = parse_csrutil_status(output)
        if error:
            posture.warnings.append(f"csrutil status {error}")
        commands.append("csrutil authenticated-root status")
        output, error = _run([SAFE_COMMANDS["csrutil"], "authenticated-root", "status"])
        posture.authenticated_root_status = parse_authenticated_root_status(output or error)
        if error and not output:
            posture.warnings.append(f"authenticated root status {error}")
    else:
        posture.warnings.append("csrutil unavailable; SIP and authenticated root posture unknown.")

    if shutil.which("spctl"):
        commands.append("spctl --status")
        output, error = _run([SAFE_COMMANDS["spctl"], "--status"])
        posture.spctl_output = output or error
        posture.gatekeeper_status = parse_spctl_status(output)
        if error:
            posture.warnings.append(f"spctl --status {error}")

    if shutil.which("fdesetup"):
        commands.append("fdesetup status")
        output, error = _run([SAFE_COMMANDS["fdesetup"], "status"])
        posture.filevault_status = parse_fdesetup_status(output)
        if error:
            posture.warnings.append(f"fdesetup status {error}")

    if shutil.which("nvram"):
        commands.append("nvram boot-args")
        output, error = _run([SAFE_COMMANDS["nvram"], "boot-args"])
        boot_args, risky = parse_boot_args(output or error)
        posture.boot_args = boot_args
        posture.reduced_security_detected = posture.reduced_security_detected or risky
        if risky:
            posture.warnings.append("Boot arguments contain reduced-security or debugging indicators.")

    if shutil.which("sw_vers"):
        commands.append("sw_vers")
        output, error = _run([SAFE_COMMANDS["sw_vers"]])
        posture.software_update_state = output or error or "unknown"

    if shutil.which("diskutil"):
        commands.append("diskutil apfs list")
        output, error = _run([SAFE_COMMANDS["diskutil"], "apfs", "list"], timeout=12)
        lowered = (output or error).lower()
        if "sealed" in lowered:
            posture.ssv_status = "sealed_or_reported"
        elif error:
            posture.ssv_status = "unknown"
            posture.warnings.append(f"SSV posture unavailable: {error}")

    posture.reduced_security_detected = posture.reduced_security_detected or posture.sip_status == "disabled" or posture.authenticated_root_status == "disabled"
    return posture, commands


def findings_from_posture(posture: SystemIntegrityPosture) -> list[RootkitSuspectFinding]:
    findings: list[RootkitSuspectFinding] = []
    checks = [
        ("sip_status", posture.sip_status, "System Integrity Protection disabled", "Apple SIP helps protect system files and folders from unauthorized modification."),
        ("authenticated_root_status", posture.authenticated_root_status, "Authenticated root disabled", "Authenticated root and the signed system volume protect system content on modern macOS."),
        ("gatekeeper_status", posture.gatekeeper_status, "Gatekeeper disabled", "Gatekeeper helps reduce execution of untrusted downloaded software."),
        ("filevault_status", posture.filevault_status, "FileVault disabled", "FileVault protects data at rest if the device is lost or accessed offline."),
    ]
    for field, status, title, why in checks:
        if status != "disabled":
            continue
        severity = "high" if field in {"sip_status", "authenticated_root_status"} else "medium"
        findings.append(
            RootkitSuspectFinding(
                finding_id=stable_id("system_integrity", field, status),
                title=title,
                severity=severity,
                confidence="high",
                category="system_integrity",
                description=f"{title} was observed during read-only system integrity posture review.",
                evidence=[f"{field}={status}"],
                why_it_matters=why,
                rootkit_relevance="Weakened platform integrity controls can make rootkit-like persistence and tamper harder to prevent or investigate.",
                false_positive_notes=["Security controls can be intentionally disabled for development, recovery, lab, or managed workflows."],
                recommended_fix="Review why this control is disabled. Re-enable through Apple-supported workflows if it was not intentional.",
                examine_further_steps=["Confirm macOS version/build.", "Review recent admin activity and change tickets.", "Preserve posture evidence before making changes."],
                apple_evidence_export_recommended=True,
                mitre_mappings=["T1562 Impair Defenses", "T1014 Rootkit"],
                nist_mappings=["SI-7 Software, Firmware, and Information Integrity", "CM-6 Configuration Settings"],
                cisa_mappings=["Secure configuration", "Incident response evidence"],
                cmmc_mappings=["System and Information Integrity", "Configuration Management"],
            )
        )
    if posture.boot_args:
        findings.append(
            RootkitSuspectFinding(
                finding_id=stable_id("system_integrity", "boot_args", posture.boot_args),
                title="Boot arguments require review",
                severity="high" if posture.reduced_security_detected else "medium",
                confidence="medium",
                category="system_integrity",
                description="Boot arguments were present and should be reviewed for reduced-security or debugging indicators.",
                evidence=[posture.boot_args],
                why_it_matters="Boot arguments can alter kernel, security, or debugging behavior.",
                rootkit_relevance="Reduced-security boot settings can weaken defenses that normally make advanced persistence harder.",
                false_positive_notes=["Developers and support teams may set boot arguments temporarily for debugging."],
                recommended_fix="Confirm the boot arguments are expected. Do not modify boot settings until evidence is preserved and ownership is understood.",
                examine_further_steps=["Review nvram boot-args output.", "Correlate with SIP/authenticated root status and recent admin activity."],
                apple_evidence_export_recommended=True,
                mitre_mappings=["T1562 Impair Defenses"],
                nist_mappings=["CM-6 Configuration Settings", "SI-7 Software, Firmware, and Information Integrity"],
                cisa_mappings=["Secure configuration"],
                cmmc_mappings=["Configuration Management"],
            )
        )
    return findings

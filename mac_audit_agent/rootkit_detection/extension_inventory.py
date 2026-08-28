from __future__ import annotations

import plistlib
import re
import shutil
import stat
import subprocess
from pathlib import Path

from mac_audit_agent.rootkit_detection.models import ExtensionInventoryItem, RootkitSuspectFinding, stable_id


EXTENSION_PATHS = [
    (Path("/Library/Extensions"), "kernel_extension"),
    (Path("/System/Library/Extensions"), "kernel_extension"),
    (Path("/Library/SystemExtensions"), "system_extension"),
    (Path("/Library/DriverExtensions"), "driverkit"),
]


def _run(command: list[str], timeout: int = 10) -> tuple[str, str]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        return (completed.stdout or "").strip(), (completed.stderr or "").strip()
    except FileNotFoundError:
        return "", "unavailable: command not found"
    except subprocess.TimeoutExpired:
        return "", "unavailable: command timed out"
    except Exception as exc:
        return "", f"unavailable: {type(exc).__name__}: {exc}"


def parse_systemextensionsctl_list(text: str) -> list[ExtensionInventoryItem]:
    items: list[ExtensionInventoryItem] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("---", "*", "enabled", "activated")):
            continue
        match = re.search(r"([A-Z0-9]{10})\s+([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", stripped)
        if not match:
            continue
        team_id, bundle_id, state = match.groups()
        ext_type = "endpoint_security_extension" if "endpoint" in stripped.lower() else "network_extension" if "network" in stripped.lower() else "system_extension"
        items.append(
            ExtensionInventoryItem(
                extension_id=stable_id("systemextensionsctl", bundle_id, team_id),
                type=ext_type,
                bundle_id=bundle_id,
                team_id=team_id,
                loaded="activated" in state.lower() or "enabled" in state.lower(),
                enabled="enabled" in state.lower(),
                signed_status="signed" if team_id else "unknown",
                source_tool="systemextensionsctl",
                visibility_sources=["systemextensionsctl"],
                evidence=[stripped],
            )
        )
    return items


def parse_kmutil_showloaded(text: str) -> list[ExtensionInventoryItem]:
    items: list[ExtensionInventoryItem] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "bundle id" in stripped.lower():
            continue
        bundle_match = re.search(r"([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)", stripped)
        if not bundle_match:
            continue
        bundle_id = bundle_match.group(1)
        tokens = stripped.split()
        address = next((token for token in tokens if token.startswith("0x")), "")
        architecture = next((token for token in tokens if token in {"arm64", "arm64e", "x86_64", "i386"}), "unknown")
        collection_match = re.search(r"\b(boot|system|sys|auxiliary|aux)\b", stripped, re.IGNORECASE)
        collection = collection_match.group(1).lower() if collection_match else "unknown"
        items.append(
            ExtensionInventoryItem(
                extension_id=stable_id("kmutil", bundle_id, stripped),
                type="kernel_extension",
                bundle_id=bundle_id,
                loaded=True,
                enabled=True,
                source_tool="kmutil",
                collection={"sys": "system", "aux": "auxiliary"}.get(collection, collection),
                address=address,
                architecture=architecture,
                visibility_sources=["kmutil"],
                evidence=[stripped],
            )
        )
    return items


def _signature_metadata(path: Path) -> dict[str, str]:
    output, error = _run(["/usr/bin/codesign", "-dv", "--verbose=4", str(path)])
    text = "\n".join(value for value in (output, error) if value)
    team_id = next((line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("TeamIdentifier=")), "")
    authority = next((line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("Authority=")), "")
    try:
        verification = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], text=True, capture_output=True, timeout=10, check=False)
        valid = verification.returncode == 0
        verify_output, verify_error = verification.stdout or "", verification.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        valid = False
        verify_output, verify_error = "", str(exc)
    failure = (verify_error or verify_output).lower()
    if valid:
        status = "signed" if team_id or authority else "ad_hoc"
    elif "not signed at all" in failure or "is not signed" in failure:
        status = "unsigned"
    elif any(marker in failure for marker in ("a sealed resource is missing", "resource envelope is obsolete", "invalid signature", "code or signature modified")):
        status = "invalid"
    else:
        status = "unknown"
    return {"signed_status": status, "team_id": team_id, "authority": authority, "verification": verify_error or verify_output}


def _bundle_metadata(path: Path) -> dict[str, str]:
    plist_path = path / "Contents/Info.plist"
    if not plist_path.exists():
        plist_path = path / "Info.plist"
    try:
        with plist_path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return {"bundle_id": path.stem, "executable_path": "", "plist_status": "missing or invalid Info.plist"}
    bundle_id = str(payload.get("CFBundleIdentifier", path.stem))
    executable = str(payload.get("CFBundleExecutable", ""))
    executable_path = ""
    if executable:
        candidates = [path / "Contents/MacOS" / executable, path / "Contents" / executable, path / executable]
        executable_path = str(next((candidate for candidate in candidates if candidate.exists()), candidates[0]))
    return {"bundle_id": bundle_id, "executable_path": executable_path, "plist_status": "available"}


def _path_item(path: Path, ext_type: str) -> ExtensionInventoryItem:
    risk_flags: list[str] = []
    owner = ""
    permissions = ""
    try:
        st = path.stat()
        permissions = stat.filemode(st.st_mode)
        owner = str(st.st_uid)
        if st.st_mode & stat.S_IWOTH:
            risk_flags.append("extension path writable by others")
        if st.st_mode & stat.S_IWGRP:
            risk_flags.append("extension path group-writable")
        if st.st_uid != 0 and str(path).startswith("/Library/"):
            risk_flags.append("privileged extension is not owned by root")
        if str(path).startswith(("/tmp", "/var/tmp", "/Users/Shared")):
            risk_flags.append("extension in unusual writable path")
    except OSError as exc:
        risk_flags.append(f"metadata unavailable: {exc}")
    platform_protected = str(path).startswith("/System/Library/Extensions/")
    metadata = _bundle_metadata(path)
    bundle_id = metadata["bundle_id"]
    executable_path = metadata["executable_path"]
    if metadata["plist_status"] != "available":
        risk_flags.append(metadata["plist_status"])
    if executable_path and not Path(executable_path).is_file() and not platform_protected:
        risk_flags.append("declared extension executable is missing")
    signature = {"signed_status": "platform_protected", "team_id": "", "authority": "", "verification": "protected by the sealed system volume path"} if platform_protected else _signature_metadata(path)
    if signature["signed_status"] in {"unsigned", "invalid"}:
        risk_flags.append(f"extension signature is {signature['signed_status']}")
    if "EndpointSecurity" in str(path) or "endpoint" in bundle_id.lower():
        ext_type = "endpoint_security_extension"
    elif "Network" in str(path) or "network" in bundle_id.lower():
        ext_type = "network_extension"
    return ExtensionInventoryItem(
        extension_id=stable_id("filesystem_extension", path),
        type=ext_type,
        bundle_id=bundle_id,
        path=str(path),
        loaded=False,
        enabled=False,
        signed_status=signature["signed_status"],
        team_id=signature["team_id"],
        owner=owner,
        permissions=permissions,
        source_tool="filesystem",
        executable_path=executable_path,
        visibility_sources=["filesystem"],
        risk_flags=risk_flags,
        evidence=[f"found on disk: {path}", f"bundle id: {bundle_id}", f"Team ID: {signature['team_id'] or 'unavailable'}"],
    )


def collect_extension_inventory() -> tuple[list[ExtensionInventoryItem], list[str], list[str]]:
    items: list[ExtensionInventoryItem] = []
    commands: list[str] = []
    limitations: list[str] = []
    if shutil.which("systemextensionsctl"):
        commands.append("systemextensionsctl list")
        output, error = _run(["/usr/bin/systemextensionsctl", "list"])
        items.extend(parse_systemextensionsctl_list(output))
        if error and not output:
            limitations.append(f"systemextensionsctl list unavailable: {error}")
    else:
        limitations.append("systemextensionsctl unavailable.")
    if shutil.which("kmutil"):
        collection_output = False
        for collection_arg, collection_name in (("boot", "boot"), ("sys", "system"), ("aux", "auxiliary")):
            command = ["/usr/bin/kmutil", "showloaded", "--show-kernel", "--list-only", "--arch-info", "-V", "release", "--collection", collection_arg]
            commands.append(" ".join(command))
            output, error = _run(command)
            parsed = parse_kmutil_showloaded(output)
            for item in parsed:
                item.collection = collection_name
            items.extend(parsed)
            collection_output = collection_output or bool(parsed)
            if error and not output:
                limitations.append(f"kmutil {collection_name} collection unavailable: {error}")
        if not collection_output:
            commands.append("kmutil showloaded")
            output, error = _run(["/usr/bin/kmutil", "showloaded"])
            items.extend(parse_kmutil_showloaded(output))
            if error and not output:
                limitations.append(f"kmutil showloaded unavailable: {error}")
    elif shutil.which("kextstat"):
        commands.append("kextstat")
        output, error = _run(["/usr/sbin/kextstat"])
        items.extend(parse_kmutil_showloaded(output))
        if error and not output:
            limitations.append(f"kextstat unavailable: {error}")
    else:
        limitations.append("kmutil/kextstat unavailable.")
    for base, ext_type in EXTENSION_PATHS:
        if not base.exists():
            limitations.append(f"{base} not present or not readable.")
            continue
        try:
            for child in base.iterdir():
                if child.name.startswith("."):
                    continue
                if child.suffix.lower() in {".kext", ".systemextension", ".dext"}:
                    items.append(_path_item(child, ext_type))
        except OSError as exc:
            limitations.append(f"{base} inventory unavailable: {exc}")
    deduped: dict[str, ExtensionInventoryItem] = {}
    for item in items:
        key = item.bundle_id or item.path or item.extension_id
        existing = deduped.get(key)
        if existing:
            existing.loaded = existing.loaded or item.loaded
            existing.enabled = existing.enabled or item.enabled
            existing.path = existing.path or item.path
            existing.team_id = existing.team_id or item.team_id
            existing.collection = existing.collection if existing.collection != "unknown" else item.collection
            existing.address = existing.address or item.address
            existing.size = existing.size or item.size
            existing.architecture = existing.architecture if existing.architecture != "unknown" else item.architecture
            existing.executable_path = existing.executable_path or item.executable_path
            existing.signed_status = item.signed_status if existing.signed_status == "unknown" else existing.signed_status
            existing.visibility_sources = sorted(set(existing.visibility_sources + item.visibility_sources))
            existing.risk_flags = sorted(set(existing.risk_flags + item.risk_flags))
            existing.evidence.extend(e for e in item.evidence if e not in existing.evidence)
        else:
            deduped[key] = item
    merged = list(deduped.values())
    for item in merged:
        if item.loaded and "filesystem" not in item.visibility_sources and not item.bundle_id.startswith("com.apple."):
            item.risk_flags.append("loaded non-Apple extension has no matching on-disk bundle in scanned locations")
        if item.path and "kmutil" not in item.visibility_sources and item.type == "kernel_extension":
            item.evidence.append("present on disk but not reported loaded by kmutil")
        item.risk_flags = sorted(set(item.risk_flags))
    return merged, commands, limitations


def findings_from_extensions(items: list[ExtensionInventoryItem]) -> list[RootkitSuspectFinding]:
    findings: list[RootkitSuspectFinding] = []
    for item in items:
        flags = list(item.risk_flags)
        if item.signed_status in {"unsigned", "invalid"}:
            flags.append(f"{item.signed_status} extension")
        if item.loaded and not item.team_id and item.type in {"kernel_extension", "system_extension", "endpoint_security_extension", "network_extension"}:
            flags.append("loaded extension with unknown Team ID")
        if not flags:
            continue
        severity = "critical" if any(flag in flags for flag in {"unsigned extension", "invalid extension"}) and item.loaded else "high"
        findings.append(
            RootkitSuspectFinding(
                finding_id=stable_id("extension", item.extension_id, ",".join(flags)),
                title="Extension requires advanced persistence review",
                severity=severity,
                confidence="medium",
                category=item.type if item.type in {"kernel_extension", "system_extension"} else "system_extension",
                description="A kernel, system, network, DriverKit, or Endpoint Security extension has attributes that require analyst review.",
                evidence=item.evidence + flags,
                why_it_matters="Privileged extensions can observe or influence sensitive system behavior.",
                rootkit_relevance="Kernel or system extension abuse is mapped to advanced persistence and rootkit-like tradecraft when combined with hiding or tamper indicators.",
                false_positive_notes=["Security tools, VPN clients, EDR, virtualization, and hardware drivers commonly install privileged extensions."],
                recommended_fix="Verify developer Team ID, signature, notarization, install path, permissions, and business justification. Remove only through vendor-supported uninstall after evidence preservation.",
                examine_further_steps=["Inspect code signature.", "Correlate install time with persistence/admin/network events.", "Review MDM or user approval records."],
                apple_evidence_export_recommended=True,
                mitre_mappings=["T1547.006 Kernel Modules and Extensions", "T1014 Rootkit"],
                nist_mappings=["SI-7 Software, Firmware, and Information Integrity", "CM-7 Least Functionality"],
                cisa_mappings=["Secure configuration", "Logging and monitoring"],
                cmmc_mappings=["System and Information Integrity", "Configuration Management"],
            )
        )
    return findings

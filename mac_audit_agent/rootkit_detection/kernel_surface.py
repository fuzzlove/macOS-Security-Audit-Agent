from __future__ import annotations

import plistlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from mac_audit_agent.rootkit_detection.models import ExtensionInventoryItem, RootkitSuspectFinding, stable_id


MAX_PLIST_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BINARY_BYTES = 128 * 1024 * 1024

KNOWN_SOURCE_IDENTIFIERS = {
    "com.yungraj.macrootkit",
    "iokernelrootkitservice",
    "iokernelrootkituserclient",
}

CAPABILITY_MARKERS: dict[str, tuple[bytes, ...]] = {
    "kernel_memory": (b"KernelRead", b"KernelWrite", b"kernel_task", b"copyin", b"copyout"),
    "physical_memory": (b"PhysicalRead", b"PhysicalWrite", b"VirtualToPhysical", b"pmap_find_phys"),
    "task_memory": (b"TaskForPid", b"task_for_pid", b"MachVmWrite", b"mach_vm_write", b"MachVmProtect"),
    "runtime_patching": (b"HookKernelFunction", b"AddBreakpoint", b"KernelCall", b"mach_msg_trap"),
    "kernel_discovery": (b"GetKaslrSlide", b"GetKernelBase", b"GetKernelSymbol", b"findKernelSlide"),
    "extension_interception": (b"copyClientEntitlement", b"OSKext", b"kmod_info", b"processAlreadyLoadKext"),
    "shared_kernel_bridge": (b"CreateSharedMemory", b"MapSharedMemory", b"IOUserClient"),
}


@dataclass
class KernelSurfaceAssessment:
    bundle_id: str
    path: str
    indicators: list[str] = field(default_factory=list)
    capability_groups: list[str] = field(default_factory=list)
    exact_source_match: bool = False
    binary_bytes_examined: int = 0
    limitations: list[str] = field(default_factory=list)


def _flatten_personalities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    personalities = payload.get("IOKitPersonalities", {})
    if isinstance(personalities, dict):
        return [value for value in personalities.values() if isinstance(value, dict)]
    return []


def analyze_kext_plist(payload: dict[str, Any], *, path: str = "") -> KernelSurfaceAssessment:
    bundle_id = str(payload.get("CFBundleIdentifier", ""))
    assessment = KernelSurfaceAssessment(bundle_id=bundle_id, path=path)
    libraries = payload.get("OSBundleLibraries", {})
    library_names = {str(key).lower() for key in libraries} if isinstance(libraries, dict) else set()
    if "com.apple.kpi.unsupported" in library_names:
        assessment.indicators.append("uses unsupported kernel programming interfaces")
    if str(payload.get("OSBundleRequired", "")).lower() == "root":
        assessment.indicators.append("declares root-stage loading")
    for personality in _flatten_personalities(payload):
        if personality.get("IOUserClientClass"):
            assessment.indicators.append("publishes an IOUserClient interface")
        if str(personality.get("IOProviderClass", "")) == "IOResources":
            assessment.indicators.append("matches the broad IOResources provider")
        for key in ("IOClass", "IOUserClientClass", "IOMatchCategory"):
            value = str(personality.get(key, "")).lower()
            if value in KNOWN_SOURCE_IDENTIFIERS:
                assessment.exact_source_match = True
    if bundle_id.lower() in KNOWN_SOURCE_IDENTIFIERS:
        assessment.exact_source_match = True
    assessment.indicators = sorted(set(assessment.indicators))
    return assessment


def load_kext_plist(bundle_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    candidates = (bundle_path / "Contents/Info.plist", bundle_path / "Info.plist")
    plist_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if plist_path is None:
        return None, "Info.plist was not found"
    try:
        if plist_path.stat().st_size > MAX_PLIST_BYTES:
            return None, "Info.plist exceeds the bounded analysis limit"
        with plist_path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        return None, f"Info.plist could not be parsed: {type(exc).__name__}"
    if not isinstance(payload, dict):
        return None, "Info.plist root is not a dictionary"
    return payload, None


def scan_binary_capabilities(path: Path, *, max_bytes: int = MAX_BINARY_BYTES) -> tuple[list[str], int, list[str]]:
    limitations: list[str] = []
    try:
        size = path.stat().st_size
        if size > max_bytes:
            limitations.append(f"binary exceeds {max_bytes} byte analysis limit")
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError as exc:
        return [], 0, [f"binary unavailable: {type(exc).__name__}"]
    groups: list[str] = []
    for group, markers in CAPABILITY_MARKERS.items():
        hits = sum(marker in data for marker in markers)
        if hits >= 2:
            groups.append(group)
    return sorted(groups), len(data), limitations


def parse_ioreg_rootkit_services(text: str) -> list[str]:
    """Return service/class indicators from bounded, inert ioreg text.

    This parser intentionally does not attempt to interpret arbitrary registry
    payloads or terminal escapes. Collection is kept separate from parsing.
    """
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text[: 8 * 1024 * 1024])
    lowered = sanitized.lower()
    return sorted(identifier for identifier in KNOWN_SOURCE_IDENTIFIERS if identifier in lowered)


def collect_reviewed_ioreg_services() -> tuple[list[str], list[str], list[str]]:
    """Query only source-reviewed class names; never open or call a user client."""
    ioreg = Path("/usr/sbin/ioreg")
    if not ioreg.is_file():
        return [], [], ["ioreg is unavailable; reviewed kernel-service runtime cross-check was skipped"]
    indicators: set[str] = set()
    commands: list[str] = []
    limitations: list[str] = []
    for class_name in ("IOKernelRootKitService", "IOKernelRootKitUserClient"):
        command = [str(ioreg), "-r", "-c", class_name, "-l", "-w", "0"]
        commands.append(" ".join(command))
        try:
            completed = subprocess.run(command, capture_output=True, timeout=4, check=False)
            output = (completed.stdout or b"")[: 8 * 1024 * 1024].decode("utf-8", errors="replace")
            indicators.update(parse_ioreg_rootkit_services(output))
            if completed.returncode not in {0, 1}:
                limitations.append(f"ioreg runtime cross-check returned status {completed.returncode}")
        except subprocess.TimeoutExpired:
            limitations.append(f"ioreg runtime cross-check timed out for {class_name}")
        except OSError as exc:
            limitations.append(f"ioreg runtime cross-check failed: {type(exc).__name__}")
    return sorted(indicators), commands, sorted(set(limitations))


def finding_from_ioreg_indicators(indicators: Iterable[str]) -> RootkitSuspectFinding | None:
    observed = sorted(set(indicators) & KNOWN_SOURCE_IDENTIFIERS)
    if not observed:
        return None
    return RootkitSuspectFinding(
        finding_id=stable_id("macrootkit_ioreg", *observed),
        title="Reviewed MacRootKit IORegistry identifier is present",
        severity="critical",
        confidence="high",
        category="kernel_extension",
        description="A fixed, read-only IORegistry lookup found a service identifier matching the reviewed MacRootKit source. Preserve evidence and validate the loaded bundle; an identifier match is strong triage evidence but is not, by itself, attribution.",
        evidence=[f"IORegistry identifier: {value}" for value in observed],
        why_it_matters="The reviewed service exposes a kernel user-client bridge with memory and runtime-patching selectors.",
        rootkit_relevance="Runtime presence of a source-specific service name is more significant than an on-disk string alone.",
        false_positive_notes=["A research or test driver may deliberately reuse these public source identifiers."],
        recommended_fix="Preserve MSAA and Apple diagnostic evidence, isolate the host according to incident policy, and validate the extension from trusted recovery media before removal.",
        examine_further_steps=["Record kmutil inventory.", "Hash and verify the on-disk KEXT.", "Review installation and approval history."],
        apple_evidence_export_recommended=True,
        mitre_mappings=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions"],
        nist_mappings=["SI-4 System Monitoring", "IR-4 Incident Handling"],
        cisa_mappings=["Incident evidence preservation"],
        cmmc_mappings=["Incident Response"],
    )


def _finding_for_assessment(item: ExtensionInventoryItem, assessment: KernelSurfaceAssessment) -> RootkitSuspectFinding | None:
    combination = len(assessment.indicators)
    capabilities = len(assessment.capability_groups)
    if not assessment.exact_source_match and combination < 3 and capabilities < 3:
        return None
    exact = assessment.exact_source_match
    loaded = item.loaded
    severity = "critical" if exact and loaded else "high" if exact or (loaded and capabilities >= 3) else "medium"
    confidence = "high" if exact and combination >= 2 else "medium"
    evidence = [
        f"bundle id: {assessment.bundle_id or item.bundle_id or 'unavailable'}",
        f"extension path: {assessment.path}",
        *(f"manifest indicator: {value}" for value in assessment.indicators),
        *(f"bounded binary capability group: {value}" for value in assessment.capability_groups),
        f"loaded state reported by inventory: {loaded}",
    ]
    if exact:
        evidence.append("artifact contains an identifier derived from the reviewed MacRootKit source")
    return RootkitSuspectFinding(
        finding_id=stable_id("kernel_surface", item.extension_id, assessment.bundle_id, *assessment.indicators, *assessment.capability_groups),
        title="Privileged kernel control surface requires incident review",
        severity=severity,
        confidence=confidence,
        category="kernel_extension",
        description="A read-only manifest and bounded binary review found a combination associated with kernel-memory access, runtime patching, or a broadly exposed kernel user client. This is a suspect finding, not proof that a rootkit is active.",
        evidence=evidence,
        why_it_matters="A kernel extension that exposes memory primitives or runtime patching through an IOUserClient can undermine process, extension, and security-tool observations.",
        rootkit_relevance="The reviewed MacRootKit source combines an IOResources service, IOUserClient selectors, kernel/task memory primitives, runtime hooks, entitlement interception, and KASLR discovery.",
        false_positive_notes=[
            "Kernel debuggers, virtualization products, hardware drivers, and authorized security research tools can contain overlapping symbols.",
            "Static strings do not prove that a capability is reachable, loaded, or malicious.",
        ],
        recommended_fix="Preserve evidence, verify the bundle hash and signing chain, compare against an approved software inventory, and escalate to an experienced macOS incident responder. Do not unload an unknown KEXT on a production host without a recovery plan.",
        examine_further_steps=[
            "Export MSAA evidence and Apple diagnostics before remediation.",
            "Confirm the loaded bundle identifier using kmutil and compare it with the on-disk bundle.",
            "Review code-signing, notarization, installation history, MDM approvals, and recovery-security policy.",
            "If compromise remains plausible, acquire a forensic image from trusted recovery media.",
        ],
        apple_evidence_export_recommended=True,
        mitre_mappings=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions", "T1562.001 Impair Defenses"],
        nist_mappings=["SI-4 System Monitoring", "SI-7 Software, Firmware, and Information Integrity", "IR-4 Incident Handling"],
        cisa_mappings=["Endpoint detection and response", "Incident evidence preservation"],
        cmmc_mappings=["System and Information Integrity", "Incident Response"],
    )


def assess_extension_kernel_surfaces(
    items: Iterable[ExtensionInventoryItem],
) -> tuple[list[RootkitSuspectFinding], list[str]]:
    findings: list[RootkitSuspectFinding] = []
    limitations: list[str] = []
    binary_budget = MAX_TOTAL_BINARY_BYTES
    for item in items:
        if item.type != "kernel_extension" or not item.path or item.path.startswith("/System/Library/"):
            continue
        bundle_path = Path(item.path)
        payload, error = load_kext_plist(bundle_path)
        if error:
            limitations.append(f"{item.bundle_id or bundle_path.name}: {error}")
            continue
        assert payload is not None
        assessment = analyze_kext_plist(payload, path=str(bundle_path))
        executable = Path(item.executable_path) if item.executable_path else None
        if executable and executable.is_file() and binary_budget > 0:
            groups, examined, binary_limitations = scan_binary_capabilities(executable, max_bytes=min(MAX_BINARY_BYTES, binary_budget))
            assessment.capability_groups = groups
            assessment.binary_bytes_examined = examined
            binary_budget -= examined
            assessment.limitations.extend(binary_limitations)
        elif executable and binary_budget <= 0:
            assessment.limitations.append("aggregate binary analysis budget exhausted")
        limitations.extend(f"{item.bundle_id or bundle_path.name}: {value}" for value in assessment.limitations)
        finding = _finding_for_assessment(item, assessment)
        if finding:
            findings.append(finding)
    return findings, sorted(set(limitations))

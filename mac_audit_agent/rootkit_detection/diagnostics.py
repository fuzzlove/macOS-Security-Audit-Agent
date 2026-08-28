from __future__ import annotations

from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.rootkit_detection.extension_inventory import collect_extension_inventory, findings_from_extensions
from mac_audit_agent.rootkit_detection.dylib_hijack import DylibHijackScanner, rootkit_findings_from_dylibs
from mac_audit_agent.rootkit_detection.models import RootkitScanResult
from mac_audit_agent.rootkit_detection.kernel_surface import (
    assess_extension_kernel_surfaces,
    collect_reviewed_ioreg_services,
    finding_from_ioreg_indicators,
)
from mac_audit_agent.rootkit_detection.persistence_correlation import correlate_rootkit_suspects
from mac_audit_agent.rootkit_detection.port_visibility import review_port_visibility
from mac_audit_agent.rootkit_detection.system_integrity import collect_system_integrity_posture, findings_from_posture
from mac_audit_agent.rootkit_detection.visibility_crosscheck import crosscheck_visibility


def run_rootkit_review(
    *,
    mode: str = "quick",
    local_only: bool = True,
    ports: bool = True,
    extensions: bool = True,
    system_integrity: bool = True,
    correlate: bool = True,
    dylib_hijacks: bool = True,
    kernel_surfaces: bool = True,
    allow_netcat_localhost: bool = False,
    allow_nmap_localhost: bool = False,
) -> RootkitScanResult:
    started = utc_now_iso()
    result = RootkitScanResult(
        scan_id=f"rootkit-{uuid4().hex[:12]}",
        started_at=started,
        completed_at=started,
        mode=mode,
        local_only=local_only,
    )
    if not local_only:
        result.limitations.append("External scanning is not performed by this review. Use explicit authorized tooling for external scope.")
    if system_integrity:
        posture, commands = collect_system_integrity_posture()
        result.posture = posture
        result.commands_run.extend(commands)
        result.limitations.extend(posture.warnings)
        result.findings.extend(findings_from_posture(posture))
    if extensions:
        ext_items, commands, limitations = collect_extension_inventory()
        result.extensions = ext_items
        result.commands_run.extend(commands)
        result.limitations.extend(limitations)
        result.findings.extend(findings_from_extensions(ext_items))
        if kernel_surfaces:
            surface_findings, surface_limitations = assess_extension_kernel_surfaces(ext_items)
            result.findings.extend(surface_findings)
            result.limitations.extend(surface_limitations)
            registry_indicators, registry_commands, registry_limitations = collect_reviewed_ioreg_services()
            result.commands_run.extend(registry_commands)
            result.limitations.extend(registry_limitations)
            registry_finding = finding_from_ioreg_indicators(registry_indicators)
            if registry_finding:
                result.findings.append(registry_finding)
    if ports:
        port_items, commands, limitations = review_port_visibility(
            allow_netcat_localhost=allow_netcat_localhost,
            allow_nmap_localhost=allow_nmap_localhost,
        )
        result.port_findings = port_items
        result.commands_run.extend(commands)
        result.limitations.extend(limitations)
        result.visibility_mismatches.extend(crosscheck_visibility(port_items))
    if dylib_hijacks:
        dylib_candidates, limitations = DylibHijackScanner().scan_running(max_binaries=512 if mode == "full" else 192)
        result.limitations.extend(limitations)
        result.findings.extend(rootkit_findings_from_dylibs(dylib_candidates))
    if correlate:
        result.findings.extend(
            correlate_rootkit_suspects(
                posture=result.posture,
                extensions=result.extensions,
                ports=result.port_findings,
                mismatches=result.visibility_mismatches,
            )
        )
    result.completed_at = utc_now_iso()
    result.limitations = sorted({item for item in result.limitations if item})
    result.commands_run = sorted({item for item in result.commands_run if item})
    return result

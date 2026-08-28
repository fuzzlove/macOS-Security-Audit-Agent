from __future__ import annotations

from pathlib import Path

from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.rootkit_detection.alert_templates import required_rootkit_alert_events
from mac_audit_agent.rootkit_detection.diagnostics import run_rootkit_review
from mac_audit_agent.rootkit_detection.evidence import export_evidence_package
from mac_audit_agent.rootkit_detection.extension_inventory import parse_kmutil_showloaded, parse_systemextensionsctl_list
from mac_audit_agent.rootkit_detection.kernel_surface import (
    analyze_kext_plist,
    assess_extension_kernel_surfaces,
    finding_from_ioreg_indicators,
    parse_ioreg_rootkit_services,
    scan_binary_capabilities,
)
from mac_audit_agent.rootkit_detection.models import ExtensionInventoryItem, PortVisibilityFinding, SystemIntegrityPosture
from mac_audit_agent.rootkit_detection.persistence_correlation import correlate_rootkit_suspects
from mac_audit_agent.rootkit_detection.port_visibility import parse_lsof_listeners, parse_nc_output, parse_netstat_listeners
from mac_audit_agent.rootkit_detection.report import export_rootkit_report_html, export_rootkit_report_json, export_rootkit_report_professional
from mac_audit_agent.rootkit_detection.risk_scoring import score_indicators
from mac_audit_agent.rootkit_detection.system_integrity import (
    findings_from_posture,
    parse_authenticated_root_status,
    parse_boot_args,
    parse_csrutil_status,
    parse_fdesetup_status,
    parse_spctl_status,
)
from mac_audit_agent.rootkit_detection.visibility_crosscheck import crosscheck_visibility


def test_system_integrity_parsers() -> None:
    assert parse_csrutil_status("System Integrity Protection status: enabled.") == "enabled"
    assert parse_csrutil_status("System Integrity Protection status: disabled.") == "disabled"
    assert parse_authenticated_root_status("Authenticated Root status: enabled") == "enabled"
    assert parse_authenticated_root_status("Authenticated Root status: disabled") == "disabled"
    assert parse_spctl_status("assessments enabled") == "enabled"
    assert parse_spctl_status("assessments disabled") == "disabled"
    assert parse_fdesetup_status("FileVault is On.") == "enabled"
    assert parse_fdesetup_status("FileVault is Off.") == "disabled"
    boot_args, risky = parse_boot_args("boot-args\tamfi_get_out_of_my_way=1")
    assert "amfi_get_out_of_my_way" in boot_args
    assert risky is True


def test_weakened_posture_creates_suspect_finding_without_confirming_rootkit() -> None:
    posture = SystemIntegrityPosture(sip_status="disabled", authenticated_root_status="enabled")
    findings = findings_from_posture(posture)
    assert findings
    payload = " ".join(f.title + " " + f.description for f in findings).lower()
    assert "rootkit confirmed" not in payload
    assert findings[0].severity == "high"


def test_extension_parsers_return_structured_items() -> None:
    system_ext = parse_systemextensionsctl_list("ABCDEF1234 com.example.security.extension (enabled active)")
    kmutil = parse_kmutil_showloaded("123 0 0xffffff7f com.example.driver (1.0)")
    assert system_ext[0].team_id == "ABCDEF1234"
    assert system_ext[0].bundle_id == "com.example.security.extension"
    assert kmutil[0].type == "kernel_extension"


def test_port_visibility_parsers_and_mismatch() -> None:
    lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\npython 123 alice 10u IPv4 0x0 0t0 TCP 127.0.0.1:8080 (LISTEN)"
    netstat = "tcp4 0 0 127.0.0.1.8080 *.* LISTEN\ntcp4 0 0 127.0.0.1.9999 *.* LISTEN"
    lsof_items = parse_lsof_listeners(lsof)
    netstat_items = parse_netstat_listeners(netstat)
    assert lsof_items[0].port == 8080
    assert any(item.port == 9999 for item in netstat_items)
    assert parse_nc_output("Connection to 127.0.0.1 port 22 [tcp/ssh] succeeded!") is True
    mismatches = crosscheck_visibility([PortVisibilityFinding(port=9999, protocol="tcp", netstat_seen=True, visibility_status="missing_owner", severity="medium", confidence="low")])
    assert mismatches[0].mismatch_type == "missing_owner"


def test_risk_correlation_explains_reasons() -> None:
    posture = SystemIntegrityPosture(sip_status="disabled", authenticated_root_status="disabled", reduced_security_detected=True)
    extensions = [ExtensionInventoryItem(extension_id="e1", type="kernel_extension", bundle_id="com.example.driver", loaded=True, risk_flags=["loaded extension with unknown Team ID"])]
    ports = [PortVisibilityFinding(port=4444, protocol="tcp", netstat_seen=True, nc_seen=True, visibility_status="hidden_candidate", severity="high", confidence="medium")]
    score = score_indicators(posture=posture, extensions=extensions, ports=ports)
    assert score.severity == "critical"
    findings = correlate_rootkit_suspects(posture=posture, extensions=extensions, ports=ports, mismatches=[])
    assert findings
    assert "not a confirmed rootkit" in findings[0].description.lower()


def test_rootkit_review_report_and_evidence_export(tmp_path: Path) -> None:
    result = run_rootkit_review(system_integrity=False, extensions=False, ports=False, correlate=True)
    json_path = export_rootkit_report_json(result, tmp_path / "rootkit.json")
    html_path = export_rootkit_report_html(result, tmp_path / "rootkit.html")
    docx_path = export_rootkit_report_professional(result, tmp_path / "rootkit.docx")
    xlsx_path = export_rootkit_report_professional(result, tmp_path / "rootkit.xlsx")
    manifest = export_evidence_package(result, tmp_path)
    assert json_path.exists()
    assert html_path.exists()
    assert manifest.exists()
    assert docx_path.exists() and xlsx_path.exists()
    assert "Rootkit &amp; Advanced Persistence" in html_path.read_text(encoding="utf-8")


def test_rootkit_pre_uat_registry_and_alert_templates() -> None:
    check_ids = {check.check_id for check in build_registry()}
    assert "rootkit.system_integrity_posture" in check_ids
    assert "rootkit.no_destructive_actions" in check_ids
    assert {
        "rootkit_suspect_detected",
        "hidden_port_mismatch_detected",
        "suspicious_kernel_extension_detected",
        "system_integrity_weakened",
    }.issubset(required_rootkit_alert_events())


def test_macrootkit_manifest_combination_is_detected_as_suspect() -> None:
    assessment = analyze_kext_plist(
        {
            "CFBundleIdentifier": "com.YungRaj.MacRootKit",
            "OSBundleRequired": "Root",
            "OSBundleLibraries": {"com.apple.kpi.unsupported": "8.0.0"},
            "IOKitPersonalities": {
                "MacRK": {
                    "IOClass": "IOKernelRootKitService",
                    "IOUserClientClass": "IOKernelRootKitUserClient",
                    "IOProviderClass": "IOResources",
                }
            },
        },
        path="/inert/MacRK.kext",
    )
    assert assessment.exact_source_match is True
    assert "publishes an IOUserClient interface" in assessment.indicators
    assert "uses unsupported kernel programming interfaces" in assessment.indicators


def test_bounded_binary_capability_groups_require_multiple_markers(tmp_path: Path) -> None:
    inert = tmp_path / "fixture.bin"
    inert.write_bytes(b"KernelRead KernelWrite HookKernelFunction AddBreakpoint GetKaslrSlide GetKernelBase")
    groups, examined, limitations = scan_binary_capabilities(inert)
    assert {"kernel_memory", "runtime_patching", "kernel_discovery"}.issubset(groups)
    assert examined == inert.stat().st_size
    assert limitations == []
    lone = tmp_path / "benign.bin"
    lone.write_bytes(b"mach_vm_write")
    assert scan_binary_capabilities(lone)[0] == []


def test_extension_surface_analysis_uses_only_inert_files(tmp_path: Path) -> None:
    bundle = tmp_path / "Research.kext"
    executable_dir = bundle / "Contents/MacOS"
    executable_dir.mkdir(parents=True)
    executable = executable_dir / "Research"
    executable.write_bytes(
        b"KernelRead KernelWrite PhysicalRead PhysicalWrite TaskForPid MachVmWrite "
        b"HookKernelFunction AddBreakpoint"
    )
    plist = {
        "CFBundleIdentifier": "com.example.research",
        "CFBundleExecutable": "Research",
        "OSBundleRequired": "Root",
        "OSBundleLibraries": {"com.apple.kpi.unsupported": "8.0.0"},
        "IOKitPersonalities": {"Research": {"IOUserClientClass": "ResearchUserClient", "IOProviderClass": "IOResources"}},
    }
    with (bundle / "Contents/Info.plist").open("wb") as handle:
        import plistlib

        plistlib.dump(plist, handle)
    item = ExtensionInventoryItem(
        extension_id="fixture",
        type="kernel_extension",
        bundle_id="com.example.research",
        path=str(bundle),
        executable_path=str(executable),
        loaded=True,
    )
    findings, limitations = assess_extension_kernel_surfaces([item])
    assert findings and findings[0].severity == "high"
    assert "not proof" in findings[0].description.lower()
    assert limitations == []


def test_ioreg_parser_strips_controls_and_finds_reviewed_identifiers() -> None:
    indicators = parse_ioreg_rootkit_services('\x1b]0;unsafe\x07 "IOClass" = "IOKernelRootKitService"')
    assert "iokernelrootkitservice" in indicators
    finding = finding_from_ioreg_indicators(indicators)
    assert finding is not None
    assert finding.severity == "critical"
    assert "not, by itself, attribution" in finding.description

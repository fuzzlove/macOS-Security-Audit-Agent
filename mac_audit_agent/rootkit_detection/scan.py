from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mac_audit_agent.reporting import get_reports_dir
from mac_audit_agent.rootkit_detection.diagnostics import run_rootkit_review
from mac_audit_agent.rootkit_detection.evidence import export_evidence_package
from mac_audit_agent.rootkit_detection.report import export_rootkit_report_html, export_rootkit_report_json
from mac_audit_agent.runtime.force_mode import ForceArgumentError, ForceMode, log_force_action, parse_force_argument


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run read-only Rootkit & Advanced Persistence suspect review.")
    parser.add_argument("--quick", action="store_true", help="Run quick local-only posture, extension, and port checks.")
    parser.add_argument("--full", action="store_true", help="Run all read-only local checks.")
    parser.add_argument("--ports", action="store_true", help="Run local port/listener visibility review.")
    parser.add_argument("--extensions", action="store_true", help="Run kernel/system extension inventory.")
    parser.add_argument("--system-integrity", action="store_true", help="Run macOS integrity posture checks.")
    parser.add_argument("--dylib-hijacks", action="store_true", help="Review running Mach-O executables for dynamic-library hijack indicators.")
    parser.add_argument("--correlate", action="store_true", help="Correlate posture, extension, and listener indicators.")
    parser.add_argument("--json", action="store_true", help="Print JSON result to stdout.")
    parser.add_argument("--export-evidence", action="store_true", help="Write local evidence package manifest.")
    parser.add_argument("--local-only", action="store_true", default=True, help="Keep collection local-only. This is the default.")
    parser.add_argument("--allow-nmap-localhost", action="store_true", help="Allow localhost-only nmap-equivalent checks if supported.")
    parser.add_argument("--allow-netcat-localhost", action="store_true", help="Allow localhost-only connection probes.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory for reports/evidence.")
    parser.add_argument("--force", "-f", action="store_true", help="Rerun read-only checks and bypass cached visibility results. Does not bypass safety checks.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cleaned, force_mode = parse_force_argument(raw_argv, command="rootkit scan", supported_scopes={"rescan", "diagnostics"}, default_scope="rescan", require_command=False)
    except ForceArgumentError as exc:
        print(str(exc), file=sys.stderr)
        log_force_action("rootkit scan", ForceMode(enabled=False, scope="unsupported"), result="rejected", error=str(exc))
        return 2
    args = build_parser().parse_args(cleaned)
    if getattr(args, "force", False):
        force_mode.enabled = True
    if force_mode.enabled:
        log_force_action("rootkit scan", force_mode, action_taken="rerun_read_only_rootkit_review", result="started")
        print("Force enabled: cached data will be bypassed and the operation will run fresh.", file=sys.stderr)
    mode = "full" if args.full else "quick"
    explicit = args.ports or args.extensions or args.system_integrity or args.dylib_hijacks or args.correlate
    result = run_rootkit_review(
        mode=mode,
        local_only=True,
        ports=args.ports or args.full or not explicit,
        extensions=args.extensions or args.full or not explicit,
        system_integrity=args.system_integrity or args.full or not explicit,
        dylib_hijacks=args.dylib_hijacks or args.full or not explicit,
        correlate=args.correlate or args.full or not explicit,
        allow_netcat_localhost=args.allow_netcat_localhost,
        allow_nmap_localhost=args.allow_nmap_localhost,
    )
    output_dir = args.output_dir.expanduser() if args.output_dir else get_reports_dir()
    if args.export_evidence:
        export_evidence_package(result, output_dir)
    export_rootkit_report_json(result, output_dir / f"rootkit_review_{result.scan_id}.json")
    export_rootkit_report_html(result, output_dir / f"rootkit_review_{result.scan_id}.html")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(
            f"Rootkit & Advanced Persistence review complete: findings={len(result.findings)} "
            f"mismatches={len(result.visibility_mismatches)} reports={output_dir}"
        )
    if force_mode.enabled:
        log_force_action("rootkit scan", force_mode, action_taken="rerun_read_only_rootkit_review", result="completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

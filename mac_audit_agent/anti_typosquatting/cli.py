from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .models import AssetType, GenerationConfiguration, PackageEcosystem, ProtectedAsset
from .reporting import export_csv, export_html, export_json
from .service import AntiTyposquattingService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa anti-typosquatting", description="Generate deterministic defensive lookalike-name analysis locally.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze")
    analyze.add_argument("--asset-type", choices=["domain", "package"], required=True)
    analyze.add_argument("--ecosystem", choices=[item.value for item in PackageEcosystem])
    analyze.add_argument("--name")
    analyze.add_argument("--group-id"); analyze.add_argument("--artifact-id")
    analyze.add_argument("--vendor"); analyze.add_argument("--package")
    analyze.add_argument("--private", action="store_true", help="Keep a Go module path private and prohibit public provider lookup.")
    analyze.add_argument("--locale", action="append", default=[])
    analyze.add_argument("--typing-profile", action="append", default=[])
    analyze.add_argument("--limit", type=int, default=25)
    online = analyze.add_mutually_exclusive_group(required=True)
    online.add_argument("--offline", action="store_true")
    online.add_argument("--lookup", action="store_true")
    analyze.add_argument("--consent-live-lookup", action="store_true", help="Confirm that candidate names may be sent to allowlisted registry providers.")
    analyze.add_argument("--output", choices=["json", "csv", "html"], default="json")
    analyze.add_argument("--output-path", type=Path)
    project = sub.add_parser("project-audit", help="Parse dependency manifests locally without executing package managers.")
    project.add_argument("--root", type=Path, required=True); project.add_argument("--protected-ecosystem", choices=[item.value for item in PackageEcosystem]); project.add_argument("--protected-name")
    providers = sub.add_parser("providers", help="Show registry capabilities and privacy limitations.")
    asset = sub.add_parser("asset", help="Manage the protected asset portfolio."); asset.add_argument("action", choices=["add", "list"]); asset.add_argument("--database", type=Path, required=True); asset.add_argument("--ecosystem", choices=[item.value for item in PackageEcosystem]); asset.add_argument("--name")
    registry = sub.add_parser("registry-search", help="Perform one consent-gated exact official-registry metadata lookup.")
    registry.add_argument("--ecosystem", choices=[item.value for item in PackageEcosystem], required=True); registry.add_argument("--name", required=True); registry.add_argument("--online", action="store_true"); registry.add_argument("--consent-live-lookup", action="store_true"); registry.add_argument("--private", action="store_true")
    investigation = sub.add_parser("investigation", help="Review persisted investigations."); investigation.add_argument("action", choices=["list", "show"]); investigation.add_argument("--database", type=Path, required=True); investigation.add_argument("--id")
    watchlist = sub.add_parser("watchlist", help="Inspect due watchlist entries without silently claiming provider health."); watchlist.add_argument("action", choices=["check"]); watchlist.add_argument("--database", type=Path, required=True); watchlist.add_argument("--online", action="store_true")
    report = sub.add_parser("report", help="Export a bounded offline technical analysis report."); report.add_argument("--asset-type", choices=["domain", "package"], required=True); report.add_argument("--ecosystem", choices=[item.value for item in PackageEcosystem]); report.add_argument("--name", required=True); report.add_argument("--format", choices=["json", "csv", "html"], required=True); report.add_argument("--output", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "providers":
        from .providers import CratesIoProvider, GoModuleProvider, MavenCentralProvider, NpmProvider, NuGetProvider, PackagistProvider, PyPIProvider, RDAPProvider, RubyGemsProvider
        providers = [RDAPProvider(), NpmProvider(), PyPIProvider(), CratesIoProvider(), RubyGemsProvider(), NuGetProvider(), MavenCentralProvider(), GoModuleProvider(), PackagistProvider()]
        print(json.dumps({item.__class__.__name__: item.capabilities.__dict__ for item in providers}, indent=2, sort_keys=True)); return 0
    if args.command == "project-audit":
        from .project_audit import scan_project
        assets=[]
        if args.protected_ecosystem and args.protected_name: assets=[ProtectedAsset(AssetType.PACKAGE, args.protected_name, PackageEcosystem(args.protected_ecosystem))]
        try: report=scan_project(args.root, assets)
        except (OSError, ValueError) as exc:
            print(json.dumps({"schema_version":"1.0","error_code":"PROJECT_AUDIT_INVALID","message":str(exc)},sort_keys=True),file=sys.stderr); return 2
        print(json.dumps(asdict(report), indent=2, sort_keys=True)); return 1 if report.findings else 0
    if args.command == "registry-search":
        if not args.online or not args.consent_live_lookup:
            print(json.dumps({"schema_version":"1.0","error_code":"CONSENT_REQUIRED","message":"Registry search requires --online and --consent-live-lookup."}), file=sys.stderr); return 3
        ecosystem=PackageEcosystem(args.ecosystem)
        if ecosystem == PackageEcosystem.GO_MODULE and args.private:
            print(json.dumps({"schema_version":"1.0","status":"not_queried","redacted_identifier":"<private-module>","message":"Private Go module paths are never sent to a public provider."})); return 0
        from .namespaces import adapter_for
        from .providers import CratesIoProvider, GoModuleProvider, MavenCentralProvider, NpmProvider, NuGetProvider, PackagistProvider, PyPIProvider, RubyGemsProvider
        parsed=adapter_for(ecosystem).parse_identifier(args.name)
        provider={PackageEcosystem.NPM:NpmProvider,PackageEcosystem.PYPI:PyPIProvider,PackageEcosystem.CRATES_IO:CratesIoProvider,PackageEcosystem.RUBYGEMS:RubyGemsProvider,PackageEcosystem.NUGET:NuGetProvider,PackageEcosystem.MAVEN_CENTRAL:MavenCentralProvider,PackageEcosystem.GO_MODULE:GoModuleProvider,PackageEcosystem.PACKAGIST:PackagistProvider}[ecosystem]()
        result=provider.lookup(parsed.lookup_key)
        print(json.dumps({"schema_version":"1.0","status":result.status.value,"provider":result.provider,"evidence":result.evidence,"message":result.message},indent=2,sort_keys=True)); return 0 if result.status.value in {"Published","Not Currently Published"} else 4
    if args.command == "investigation":
        from .persistence import AntiTyposquattingStore
        store=AntiTyposquattingStore(args.database)
        if args.action == "show" and not args.id:
            print(json.dumps({"error_code":"INVALID_ARGUMENT","message":"investigation show requires --id"}),file=sys.stderr); return 2
        where, params = (" WHERE id=?", (args.id,)) if args.action == "show" else ("", ())
        rows=store.connection.execute("SELECT id,status,assigned_reviewer,human_disposition,rationale,opened_at,closed_at FROM anti_typosquatting_investigations"+where+" ORDER BY opened_at",params).fetchall()
        print(json.dumps({"schema_version":"1.0","investigations":[dict(zip(("id","status","reviewer","human_disposition","rationale","opened_at","closed_at"),row)) for row in rows]},indent=2)); return 0 if rows or args.action == "list" else 5
    if args.command == "watchlist":
        from .persistence import AntiTyposquattingStore
        store=AntiTyposquattingStore(args.database)
        rows=store.connection.execute("SELECT id,candidate_name,normalized_name,ecosystem,last_checked_at,next_eligible_check,enabled FROM anti_typosquatting_watchlist WHERE enabled=1 ORDER BY id").fetchall()
        payload={"schema_version":"1.0","online":bool(args.online),"provider_state":"not_checked" if not args.online else "online_check_requires per-entry provider orchestration","entries":[dict(zip(("id","identity","normalized_identity","ecosystem","last_checked","next_eligible_check","enabled"),row)) for row in rows]}
        print(json.dumps(payload,indent=2)); return 4 if args.online and rows else 0
    if args.command == "report":
        ecosystem=PackageEcosystem(args.ecosystem) if args.ecosystem else None
        try: run=AntiTyposquattingService().analyze(ProtectedAsset(AssetType(args.asset_type),args.name,ecosystem))
        except ValueError as exc: print(json.dumps({"error_code":"INVALID_ASSET","message":str(exc)}),file=sys.stderr); return 2
        path={"json":export_json,"csv":export_csv,"html":export_html}[args.format](run,args.output); print(str(path)); return 0
    if args.command == "asset":
        from datetime import datetime, timezone
        from .persistence import AntiTyposquattingStore
        store=AntiTyposquattingStore(args.database)
        if args.action == "list":
            rows=store.connection.execute("SELECT asset_type,ecosystem,canonical_name,normalized_name FROM protected_assets ORDER BY ecosystem,normalized_name").fetchall(); print(json.dumps({"assets":[dict(zip(("asset_type","ecosystem","canonical_name","normalized_name"),row)) for row in rows]},indent=2)); return 0
        if not args.ecosystem or not args.name: print(json.dumps({"error_code":"INVALID_ASSET","message":"asset add requires --ecosystem and --name"}),file=sys.stderr); return 2
        ecosystem=PackageEcosystem(args.ecosystem); from .namespaces import adapter_for; parsed=adapter_for(ecosystem).parse_identifier(args.name)
        now=datetime.now(timezone.utc).isoformat()
        with store.connection: store.connection.execute("INSERT OR IGNORE INTO protected_assets(asset_type,ecosystem,canonical_name,normalized_name,display_name,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",("package",ecosystem.value,parsed.canonical,parsed.comparison_key,parsed.display,now,now))
        print(json.dumps({"status":"saved","ecosystem":ecosystem.value,"canonical":parsed.canonical})); return 0
    if args.lookup and not args.consent_live_lookup:
        print(json.dumps({"schema_version": "1.0", "error_code": "CONSENT_REQUIRED", "message": "Live lookup requires recorded explicit consent. Use the GUI consent workflow or --offline."}, sort_keys=True), file=sys.stderr)
        return 3
    ecosystem = PackageEcosystem(args.ecosystem) if args.ecosystem else None
    name = args.name
    if ecosystem == PackageEcosystem.MAVEN_CENTRAL and args.group_id and args.artifact_id: name = args.group_id + ":" + args.artifact_id
    if ecosystem == PackageEcosystem.PACKAGIST and args.vendor and args.package: name = args.vendor + "/" + args.package
    if not name:
        print(json.dumps({"schema_version":"1.0","error_code":"INVALID_ASSET","message":"A canonical --name or structured ecosystem fields are required."}),file=sys.stderr); return 2
    try:
        asset = ProtectedAsset(AssetType(args.asset_type), name, ecosystem)
        config = GenerationConfiguration(locales=tuple(args.locale or ["en-US-qwerty"]), typing_profiles=tuple(args.typing_profile or ["desktop"]), result_limit=max(1, min(args.limit, 100)), offline_only=True)
        run = AntiTyposquattingService().analyze(asset, config)
        if args.lookup:
            from .providers import CratesIoProvider, GoModuleProvider, MavenCentralProvider, NpmProvider, NuGetProvider, PackagistProvider, PyPIProvider, RDAPProvider, RubyGemsProvider
            provider_map={PackageEcosystem.NPM:NpmProvider,PackageEcosystem.PYPI:PyPIProvider,PackageEcosystem.CRATES_IO:CratesIoProvider,PackageEcosystem.RUBYGEMS:RubyGemsProvider,PackageEcosystem.NUGET:NuGetProvider,PackageEcosystem.MAVEN_CENTRAL:MavenCentralProvider,PackageEcosystem.GO_MODULE:GoModuleProvider,PackageEcosystem.PACKAGIST:PackagistProvider}
            provider = RDAPProvider() if asset.asset_type == AssetType.DOMAIN else provider_map[ecosystem]()
            for candidate in run.candidates[:10]:
                if ecosystem == PackageEcosystem.GO_MODULE: result = provider.lookup(candidate.normalized_name, private=args.private, private_patterns=os.environ.get("GOPRIVATE", "") + "," + os.environ.get("GONOPROXY", ""))
                else: result = provider.lookup(candidate.ascii_name or candidate.normalized_name)
                candidate.lookup_status = result.status.value
                candidate.lookup_evidence = {"provider": result.provider, "message": result.message, **result.evidence}
    except ValueError as exc:
        print(json.dumps({"schema_version": "1.0", "error_code": "INVALID_ASSET", "message": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    if args.output_path:
        exporter = {"json": export_json, "csv": export_csv, "html": export_html}[args.output]
        path = exporter(run, args.output_path)
        print(str(path))
    elif args.output == "json":
        print(json.dumps(run.to_dict(), indent=2, sort_keys=True, ensure_ascii=True))
    else:
        print(json.dumps({"schema_version": "1.0", "error_code": "OUTPUT_PATH_REQUIRED", "message": "CSV and HTML output require --output-path."}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

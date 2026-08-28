"""Operator CLI for signed threat definition lifecycle management."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .credentials import (
    CredentialStoreError,
    CredentialValidationError,
    automatic_abuse_ch_credential_status,
    remove_automatic_abuse_ch_auth_key,
    save_automatic_abuse_ch_auth_key,
)
from .locking import UpdateAlreadyRunning
from .manager import UpdateRejected, default_manager
from .signing import ManifestSigner
from .store import DEFAULT_DEFINITION_ROOT, BundleError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa definitions", description="Validate, stage, activate, import, and roll back signed MSAA threat definitions.")
    parser.add_argument("command", choices=["status", "sources", "update", "scheduled-update", "startup-update", "import", "activate", "rollback", "history", "export", "validate", "verify", "diagnostics", "credential-install", "credential-remove", "credential-status", "learn-local-yara", "verify-local-yara"])
    parser.add_argument("target", nargs="?", help="Source ID, bundle version, offline bundle path, or local corpus path, depending on command.")
    parser.add_argument("--root", type=Path, default=DEFAULT_DEFINITION_ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--activate", action="store_true", help="Activate only after all validation and signature gates pass.")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--enable-source", action="append", default=[], help="Explicitly enable a configured source for this invocation.")
    parser.add_argument("--source-config", type=Path, help="Administrator-reviewed definition_sources.json registry.")
    parser.add_argument("--require-signatures", action="store_true", help="Require detached signatures for every activated release.")
    parser.add_argument("--signing-key", type=Path, help="Release-engineering Ed25519 PEM private key; never required for offline import.")
    parser.add_argument("--key-id", help="Trusted public-key identifier matching the signing key.")
    parser.add_argument("--allow-early-update", action="store_true", help="Override the local scheduler interval; provider limits still apply.")
    parser.add_argument("--dry-run", action="store_true", help="Download, parse, compile, and validate without activating a release.")
    parser.add_argument("--benign-corpus", type=Path, help="Separate known-good corpus for local YARA negative controls.")
    parser.add_argument("--maximum-files", type=int, default=2500, help="Maximum inert corpus files read by local YARA learning.")
    parser.add_argument("--sample-bytes", type=int, default=2 * 1024 * 1024, help="Maximum byte windows sampled per local corpus file.")
    parser.add_argument("--development-allow-unsigned", action="store_true", help=argparse.SUPPRESS)
    return parser


def _signer(path: Path | None, key_id: str | None) -> ManifestSigner | None:
    if path is None:
        return None
    if not key_id:
        raise SystemExit("--signing-key requires --key-id")
    path = path.expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise SystemExit("signing key must be a bounded regular file")
    if path.stat().st_mode & 0o077:
        raise SystemExit("signing key permissions must not grant group or other access")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise SystemExit(f"unable to load unencrypted Ed25519 signing key: {type(exc).__name__}") from exc
    return ManifestSigner(key_id, key.sign)


def _main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify-local-yara":
        if not args.target:
            raise SystemExit("verify-local-yara requires a candidate run directory")
        from .local_yara_learning import verify_local_yara_run

        print(json.dumps(verify_local_yara_run(Path(args.target)), indent=2, sort_keys=True))
        return 0
    if args.command == "learn-local-yara":
        if not args.target:
            raise SystemExit("learn-local-yara requires a local corpus directory")
        from .local_yara_learning import (
            LocalYaraLearningPolicy,
            learn_local_yara_candidates,
        )

        payload = learn_local_yara_candidates(
            Path(args.target),
            args.output,
            benign_root=args.benign_corpus,
            policy=LocalYaraLearningPolicy(
                maximum_files=args.maximum_files,
                sampled_bytes_per_file=args.sample_bytes,
            ),
        )
        summary_keys = (
            "operation", "run_id", "model_version", "sample_count", "family_count",
            "candidate_count", "definition_candidate_count", "suspicious_candidate_count",
            "rejected_candidate_count", "artifact_hashes", "output_root", "manifest_path",
            "safety", "quality_warnings", "qualification",
        )
        print(json.dumps({key: payload[key] for key in summary_keys}, indent=2, sort_keys=True, default=str))
        return 0 if payload.get("candidate_count") else 1
    signature_policy = False if args.development_allow_unsigned else True if args.require_signatures else None
    manager = default_manager(
        args.root.expanduser(), enabled_sources=set(args.enable_source) if args.enable_source else None, require_signatures=signature_policy,
        source_config_path=args.source_config.expanduser() if args.source_config else None,
    )
    signer = _signer(args.signing_key, args.key_id)
    if args.command == "status":
        payload: object = manager.status()
    elif args.command == "credential-status":
        payload = automatic_abuse_ch_credential_status().to_dict()
    elif args.command == "credential-install":
        if os.geteuid() != 0:
            raise PermissionError("administrator authorization is required")
        if not sys.stdin.isatty():
            raise CredentialStoreError("credential installation requires an interactive Terminal")
        key = getpass.getpass("abuse.ch Auth-Key (input hidden): ")
        try:
            payload = save_automatic_abuse_ch_auth_key(key).to_dict()
        finally:
            key = ""
    elif args.command == "credential-remove":
        payload = remove_automatic_abuse_ch_auth_key().to_dict()
    elif args.command == "sources":
        payload = {"sources": manager.source_statuses()}
    elif args.command == "update":
        activate = bool(args.activate and not args.dry_run)
        if args.target:
            payload = manager.update_source(args.target, signer=signer, activate=activate, allow_early_update=args.allow_early_update)
        else:
            payload = {"updates": manager.update_enabled(signer=signer, activate=activate, allow_early_update=args.allow_early_update)}
        if args.dry_run and isinstance(payload, dict):
            payload["dry_run"] = True
            payload["active_definitions_unchanged"] = True
    elif args.command in {"scheduled-update", "startup-update"}:
        from .scheduler import DefinitionUpdateScheduler

        payload = {"updates": DefinitionUpdateScheduler(manager).run_due(signer=signer, activate=args.activate)}
    elif args.command == "import":
        if not args.target:
            raise SystemExit("import requires the path to a signed .bundle archive")
        payload = manager.import_offline(Path(args.target).expanduser(), activate=args.activate)
    elif args.command == "activate":
        if not args.target:
            raise SystemExit("activate requires a staged bundle version")
        payload = manager.activate(args.target)
    elif args.command == "rollback":
        payload = manager.rollback()
    elif args.command == "history":
        payload = {"history": manager.store.history()}
    elif args.command == "export":
        if not args.target or not args.output:
            raise SystemExit("export requires a version and --output path")
        payload = {"status": "EXPORTED", "path": str(manager.store.export_bundle(args.target, args.output.expanduser()))}
    elif args.command == "diagnostics":
        if not args.output:
            raise SystemExit("diagnostics requires --output ending in .html, .docx, .xlsx, or .json")
        from .diagnostics import export_diagnostics

        payload = {"status": "EXPORTED", "path": str(export_diagnostics(manager, args.output.expanduser())), "formats_supported": ["html", "docx", "xlsx", "json"]}
    elif args.command == "verify":
        payload = manager.verify(args.target)
    else:
        if not args.target:
            raise SystemExit("validate requires a staged or active bundle version")
        definitions = manager.store.definitions(args.target)
        payload = manager.validator.validate(definitions).to_dict()
    if os.geteuid() == 0 and args.command in {"update", "scheduled-update", "startup-update", "import", "activate", "rollback", "verify", "credential-install", "credential-remove"}:
        # Publish a sanitized, world-readable health snapshot so the unprivileged
        # desktop can observe the completed administrator operation on Refresh.
        manager.status()
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    state = payload.get("state") if isinstance(payload, dict) else None
    return 2 if state == "FAILED" else 1 if state in {"DEGRADED", "STALE", "NEVER_UPDATED", "PERMISSION_BLOCKED", "UNAVAILABLE"} else 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        return _main(arguments)
    except (BundleError, UpdateRejected, UpdateAlreadyRunning, PermissionError, CredentialStoreError, CredentialValidationError) as exc:
        payload = {
            "status": "REJECTED",
            "error_code": (
                "UPDATE_ALREADY_RUNNING" if isinstance(exc, UpdateAlreadyRunning)
                else "DEF_IMPORT_REJECTED" if arguments and arguments[0] == "import"
                else "DEF_OPERATION_REJECTED"
            ),
            "message": str(exc),
            "active_definitions_unchanged": True,
        }
        if "--json" in arguments:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"MSAA definition operation rejected: {exc}\nActive definitions were not changed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]

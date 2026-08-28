from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict
from pathlib import Path

from mac_audit_agent.integrity.canonical import manifest_files, signed_payload_from_manifest
from mac_audit_agent.integrity.codex_provenance import create_codex_provenance
from mac_audit_agent.integrity.cleanup import cleanup_generated, cleanup_legacy_integrity
from mac_audit_agent.integrity.consumer_compare import compare_integrity_consumers
from mac_audit_agent.integrity.event_reconciliation import SQLiteIntegrityEventStore, reconcile_integrity_events_after_verified_repair
from mac_audit_agent.integrity.auto_sign import AutoSignError, auto_sign_integrity
from mac_audit_agent.integrity.dev_manifest import (
    CANONICAL_MANIFEST_RELATIVE_PATH,
    CANONICAL_SIGNATURE_RELATIVE_PATH,
    doctor_status,
    rehash_manifest,
    resolve_manifest_path,
    resolve_signature_path,
    verify_manifest,
    write_audit_record,
)
from mac_audit_agent.integrity.developer_machine_identity import load_trusted_developer_machines, revoke_developer_machine
from mac_audit_agent.integrity.developer_machine_signing import (
    DeveloperMachineSigningError,
    create_developer_machine_key,
    sign_canonical_manifest,
)
from mac_audit_agent.integrity.headless_guard import HeadlessIntegrityError, ensure_integrity_cli_headless_safe
from mac_audit_agent.integrity.manifest_discovery import discover_integrity_manifests
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy
from mac_audit_agent.integrity.release_sign import DEFAULT_ARTIFACT_MANIFEST, DEFAULT_ARTIFACT_SIGNATURE
from mac_audit_agent.integrity.release_verify import verify_release
from mac_audit_agent.integrity.release_gate_mapping import map_release_gate_exception
from mac_audit_agent.integrity.result_cache import build_current_integrity_status, write_current_integrity_status, write_current_integrity_status_db
from mac_audit_agent.integrity.runtime_sync import run_runtime_sync_check
from mac_audit_agent.integrity.repair_and_sign import repair_and_sign_integrity
from mac_audit_agent.integrity.public_release_gate import run_public_release_gate
from mac_audit_agent.integrity.signing import DEFAULT_PUBLIC_KEY_PATH
from mac_audit_agent.integrity.doctor import build_integrity_doctor_status
from mac_audit_agent.integrity.preflight import run_integrity_preflight
from mac_audit_agent.integrity.harden_validate import harden_and_validate
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.independent_verify import run_independent_verify
from mac_audit_agent.integrity.status_resolver import resolve_integrity_status
from mac_audit_agent.integrity.trust_policy import load_trust_policy
from mac_audit_agent.integrity.yubikey_signing import (
    DEFAULT_PIV_MANAGEMENT_KEY_WARNING,
    ManagementKey,
    ManagementKeyInputError,
    YubiKeySigningError,
    enroll_yubikey,
    get_yubikey_diagnostics,
    list_yubikey_tokens,
    parse_management_key_input,
    sign_manifest_with_enrolled_yubikeys,
)


def _path(value: str) -> Path:
    return Path(value).expanduser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MSAA tamper-evident integrity manifest tooling.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    rehash = subparsers.add_parser("rehash", help="Generate an authorized developer/build integrity manifest.")
    rehash.add_argument("--root", type=_path, default=Path.cwd())
    rehash.add_argument("--manifest", type=_path, default=None, help=f"Default: {CANONICAL_MANIFEST_RELATIVE_PATH}")
    rehash.add_argument("--signature", type=_path, default=None, help=f"Default: {CANONICAL_SIGNATURE_RELATIVE_PATH}")
    rehash.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default=None)
    rehash.add_argument("--author", required=True)
    rehash.add_argument("--reason", required=True)
    rehash.add_argument("--developer-mode", action="store_true", help="Explicitly authorize source-tree rehashing.")
    rehash.add_argument("--require-clean-git", action="store_true")
    rehash.add_argument("--build-id", default="")
    rehash.add_argument("--release-id", default="")
    rehash.add_argument("--sign-manifest", action="store_true")
    rehash.add_argument("--private-key", type=_path, default=None)
    rehash.add_argument("--public-key", type=_path, default=None)
    rehash.add_argument("--release-mode", action="store_true")
    rehash.add_argument("--legacy-output", action="store_true", help="Explicitly write a legacy manifest path. Pre-UAT will not validate this output.")
    rehash.add_argument("--allow-post-verify-failure", action="store_true", help="Do not fail rehash when post-rehash Pre-UAT-compatible verification fails.")
    rehash.add_argument("--audit-log", type=_path, default=None)

    verify = subparsers.add_parser("verify", help="Verify protected files against the trusted manifest.")
    verify.add_argument("--root", type=_path, default=Path.cwd())
    verify.add_argument("--manifest", type=_path, default=None, help=f"Default: {CANONICAL_MANIFEST_RELATIVE_PATH}")
    verify.add_argument("--signature", type=_path, default=None, help=f"Default: {CANONICAL_SIGNATURE_RELATIVE_PATH}")
    verify.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    verify.add_argument("--public-key", type=_path, default=None)
    verify.add_argument("--require-signature", action="store_true")
    verify.add_argument("--strict", action="store_true", help="Use the canonical developer-machine status resolver.")
    verify.add_argument("--update-current-status", action="store_true", help="Write verified live status to display-only cache and active DB.")
    verify.add_argument("--audit-log", type=_path, default=None)
    verify.add_argument("--json", action="store_true")

    sign = subparsers.add_parser("sign", help="Build and sign the canonical manifest using an enrolled developer-machine key.")
    sign.add_argument("--root", type=_path, default=Path.cwd())
    sign.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    sign.add_argument("--author", required=True)
    sign.add_argument("--reason", required=True)
    sign.add_argument("--build-id", default="")
    sign.add_argument("--release-id", default="")
    sign.add_argument("--developer-machine", action="store_true", help="Sign with the enrolled trusted developer-machine key.")
    sign.add_argument("--require-yubikey-quorum", action="store_true", help=argparse.SUPPRESS)
    sign.add_argument("--audit-log", type=_path, default=None)

    auto_sign = subparsers.add_parser("auto-sign", help="Discover, repair, sign, and verify the canonical integrity manifest.")
    auto_sign.add_argument("--root", type=_path, default=Path.cwd())
    auto_sign.add_argument("--policy", choices=["dev", "pre_release", "public_release"], default="dev")
    auto_sign.add_argument("--author", required=True)
    auto_sign.add_argument("--reason", required=True)
    auto_sign.add_argument("--build-id", default="")
    auto_sign.add_argument("--developer-machine", action="store_true")
    auto_sign.add_argument("--verify-pre-uat-compatible", action="store_true")
    auto_sign.add_argument("--migrate-legacy", action="store_true", default=True)
    auto_sign.add_argument("--exclude-generated", action="store_true", default=True)
    auto_sign.add_argument("--approve-current-source", action="store_true")
    auto_sign.add_argument(
        "--typed-confirmation",
        default="",
        help='Required with --approve-current-source; must exactly equal "APPROVE SOURCE BASELINE".',
    )
    auto_sign.add_argument("--dry-run", action="store_true")
    auto_sign.add_argument("--json", action="store_true")
    auto_sign.add_argument("--verbose", action="store_true")
    auto_sign.add_argument("--audit-log", type=_path, default=None)

    preflight = subparsers.add_parser("preflight", help="Run headless integrity trust-chain preflight without mutating manifests.")
    preflight.add_argument("--root", type=_path, default=Path.cwd())
    preflight.add_argument("--policy", choices=["dev", "pre_release", "public_release"], default="dev")
    preflight.add_argument("--strict", action="store_true")
    preflight.add_argument("--approve-current-source", action="store_true")
    preflight.add_argument("--json", action="store_true")

    hash_scope = subparsers.add_parser("hash-scope", help="Classify every project file as included, excluded, generated, runtime, build, or unknown.")
    hash_scope.add_argument("--root", type=_path, default=Path.cwd())
    hash_scope.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    hash_scope.add_argument("--json", action="store_true")

    independent = subparsers.add_parser("independent-verify", help="Verify manifest/signature/files using a headless independent verifier.")
    independent.add_argument("--root", type=_path, default=Path.cwd())
    independent.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    independent.add_argument("--strict", action="store_true")
    independent.add_argument("--json", action="store_true")

    runtime_sync = subparsers.add_parser("runtime-sync-check", help="Check whether installed runtime wrappers match source-tree integrity wrappers.")
    runtime_sync.add_argument("--root", type=_path, default=Path.cwd())
    runtime_sync.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="public_release")
    runtime_sync.add_argument("--json", action="store_true")

    compare = subparsers.add_parser("compare-consumers", help="Compare live integrity status across CLI, Pre-UAT, UI/backend, and event consumers.")
    compare.add_argument("--root", type=_path, default=Path.cwd())
    compare.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    compare.add_argument("--json", action="store_true")

    cleanup_legacy = subparsers.add_parser("cleanup-legacy", help="Archive legacy integrity manifests/signatures outside active scope.")
    cleanup_legacy.add_argument("--root", type=_path, default=Path.cwd())
    cleanup_legacy.add_argument("--dry-run", action="store_true")
    cleanup_legacy.add_argument("--archive", action="store_true")
    cleanup_legacy.add_argument("--confirm", default="")

    cleanup_gen = subparsers.add_parser("cleanup-generated", help="Remove selected generated artifacts from the source tree.")
    cleanup_gen.add_argument("--root", type=_path, default=Path.cwd())
    cleanup_gen.add_argument("--egg-info", action="store_true")
    cleanup_gen.add_argument("--dry-run", action="store_true")
    cleanup_gen.add_argument("--confirm", default="")

    reconcile = subparsers.add_parser("reconcile-events", help="Mark stale active integrity events superseded after live verification passes.")
    reconcile.add_argument("--root", type=_path, default=Path.cwd())
    reconcile.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="public_release")
    reconcile.add_argument("--active-db", type=_path, default=None)
    reconcile.add_argument("--json", action="store_true")

    repair_sign = subparsers.add_parser("repair-and-sign", help="Repair generated drift, rebuild the canonical manifest, sign, and verify.")
    repair_sign.add_argument("--root", type=_path, default=Path.cwd())
    repair_sign.add_argument("--policy", choices=["dev", "pre_release", "public_release"], default="dev")
    repair_sign.add_argument("--author", required=True)
    repair_sign.add_argument("--reason", required=True)
    repair_sign.add_argument("--build-id", default="")
    repair_sign.add_argument("--developer-machine", action="store_true")
    repair_sign.add_argument("--verify-pre-uat-compatible", action="store_true")
    repair_sign.add_argument("--migrate-legacy", action="store_true", default=True)
    repair_sign.add_argument("--exclude-generated", action="store_true", default=True)
    repair_sign.add_argument("--approve-current-source", action="store_true")
    repair_sign.add_argument("--typed-confirmation", default="")
    repair_sign.add_argument("--dry-run", action="store_true")
    repair_sign.add_argument("--json", action="store_true")
    repair_sign.add_argument("--verbose", action="store_true")
    repair_sign.add_argument("--audit-log", type=_path, default=None)

    harden = subparsers.add_parser("harden-and-validate", help="Run preflight, repair/sign, round-trip verification, Pre-UAT/UI compatibility, and independent verification.")
    harden.add_argument("--root", type=_path, default=Path.cwd())
    harden.add_argument("--policy", choices=["dev", "pre_release", "public_release"], default="dev")
    harden.add_argument("--author", required=True)
    harden.add_argument("--reason", required=True)
    harden.add_argument("--build-id", default="")
    harden.add_argument("--developer-machine", action="store_true")
    harden.add_argument("--exclude-generated", action="store_true", default=True)
    harden.add_argument("--migrate-legacy", action="store_true", default=True)
    harden.add_argument("--verify-pre-uat-compatible", action="store_true")
    harden.add_argument("--approve-current-source", action="store_true")
    harden.add_argument("--typed-confirmation", default="")
    harden.add_argument("--run-independent-verify", action="store_true")
    harden.add_argument("--run-tamper-self-test", action="store_true")
    harden.add_argument("--json", action="store_true")
    harden.add_argument("--verbose", action="store_true")

    machine = subparsers.add_parser("machine", help="Manage trusted developer-machine signing identities.")
    machine_sub = machine.add_subparsers(dest="machine_command", required=True)
    machine_enroll = machine_sub.add_parser("enroll", help="Enroll this Mac for developer-machine manifest signing.")
    machine_enroll.add_argument("--root", type=_path, default=Path.cwd())
    machine_enroll.add_argument("--developer", required=True)
    machine_enroll.add_argument("--organization", required=True)
    machine_enroll.add_argument("--machine-label", required=True)
    machine_enroll.add_argument("--use-secure-enclave", action="store_true")
    machine_status = machine_sub.add_parser("status", help="Show trusted developer-machine registry status.")
    machine_status.add_argument("--root", type=_path, default=Path.cwd())
    machine_revoke = machine_sub.add_parser("revoke", help="Revoke a trusted developer-machine identity.")
    machine_revoke.add_argument("--root", type=_path, default=Path.cwd())
    machine_revoke.add_argument("--developer-machine-id", required=True)
    machine_revoke.add_argument("--reason", required=True)

    discover = subparsers.add_parser("discover", help="Discover canonical and legacy integrity manifests.")
    discover.add_argument("--root", type=_path, default=Path.cwd())
    discover.add_argument("--json", action="store_true")

    yubikey = subparsers.add_parser("yubikey", help="Manage YubiKey enrollment and verification.")
    yubikey_sub = yubikey.add_subparsers(dest="yubikey_command", required=True)
    yubikey_list = yubikey_sub.add_parser("list", help="List visible YubiKey tokens.")
    yubikey_list.add_argument("--root", type=_path, default=Path.cwd())
    yubikey_enroll = yubikey_sub.add_parser("enroll", help="Enroll a YubiKey PIV signing certificate.")
    yubikey_enroll.add_argument("--root", type=_path, default=Path.cwd())
    yubikey_enroll.add_argument("--label", required=True)
    yubikey_enroll.add_argument("--developer-id", required=True)
    yubikey_enroll.add_argument("--slot", default="9c")
    yubikey_enroll.add_argument("--management-key", default=None, help="Use 'default' or 'hex:<HEX>'. Values are never printed.")
    yubikey_enroll.add_argument("--prompt-management-key", action="store_true", help="Prompt once for the PIV management key; blank uses the YubiKey default.")
    yubikey_enroll.add_argument("--pin", default=None, help="PIV PIN for certificate generation. Prefer --prompt-pin for interactive use.")
    yubikey_enroll.add_argument("--prompt-pin", action="store_true", help="Prompt once for the PIV PIN.")
    yubikey_enroll.add_argument("--pin-policy", default="ALWAYS", choices=["DEFAULT", "NEVER", "ONCE", "ALWAYS"])
    yubikey_enroll.add_argument("--touch-policy", default="ALWAYS", choices=["DEFAULT", "NEVER", "ALWAYS", "CACHED"])
    yubikey_verify = yubikey_sub.add_parser("verify", help="Verify current YubiKey quorum configuration.")
    yubikey_verify.add_argument("--root", type=_path, default=Path.cwd())

    codex = subparsers.add_parser("codex-provenance", help="Record Codex-assisted change provenance metadata.")
    codex_sub = codex.add_subparsers(dest="codex_command", required=True)
    codex_create = codex_sub.add_parser("create", help="Create a metadata-only Codex provenance record.")
    codex_create.add_argument("--root", type=_path, default=Path.cwd())
    codex_create.add_argument("--operator", required=True)
    codex_create.add_argument("--summary", required=True)
    codex_create.add_argument("--approved-change-id", default="")
    codex_create.add_argument("--notes", default="")

    repair = subparsers.add_parser("repair-status", help="Diagnose and repair manifest path/status divergence.")
    repair.add_argument("--root", type=_path, default=Path.cwd())
    repair.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    repair.add_argument("--discover", action="store_true")
    repair.add_argument("--migrate-legacy", action="store_true")
    repair.add_argument("--exclude-generated", action="store_true")
    repair.add_argument("--developer-machine", action="store_true")
    repair.add_argument("--require-yubikey-quorum", action="store_true", help=argparse.SUPPRESS)

    doctor = subparsers.add_parser("doctor", help="Print read-only Doctor integrity status.")
    doctor.add_argument("--root", type=_path, default=Path.cwd())
    doctor.add_argument("--manifest", type=_path, default=None)
    doctor.add_argument("--signature", type=_path, default=None)
    doctor.add_argument("--policy", choices=["dev", "pre_release", "public_release", "runtime"], default="dev")
    doctor.add_argument("--public-key", type=_path, default=None)
    doctor.add_argument("--require-signature", action="store_true")
    doctor.add_argument("--json", action="store_true")

    release_verify = subparsers.add_parser("release_verify", help="Verify the canonical policy manifest used by Pre-UAT.")
    release_verify.add_argument("--root", type=_path, default=Path.cwd())
    release_verify.add_argument("--policy", "--mode", dest="policy", default="dev", choices=["dev", "pre_release", "public_release", "release"])
    release_verify.add_argument("--manifest", type=_path, default=None)
    release_verify.add_argument("--signature", type=_path, default=None)
    release_verify.add_argument("--public-key", type=_path, default=DEFAULT_PUBLIC_KEY_PATH)
    release_verify.add_argument("--artifact-manifest", type=_path, default=DEFAULT_ARTIFACT_MANIFEST)
    release_verify.add_argument("--artifact-signature", type=_path, default=DEFAULT_ARTIFACT_SIGNATURE)

    release_gate = subparsers.add_parser("public-release-gate", help="Run source integrity, build/test, artifact signing, and release-readiness checks.")
    release_gate.add_argument("--root", type=_path, default=Path.cwd())
    release_gate.add_argument("--author", required=True)
    release_gate.add_argument("--reason", required=True)
    release_gate.add_argument("--build-id", default="")
    release_gate.add_argument("--developer-machine", action="store_true")
    release_gate.add_argument("--build", action="store_true")
    release_gate.add_argument("--test", action="store_true")
    release_gate.add_argument("--twine-check", action="store_true")
    release_gate.add_argument("--clean-install", action="store_true")
    release_gate.add_argument("--sign-artifacts", action="store_true")
    release_gate.add_argument("--verify-all", action="store_true")
    release_gate.add_argument("--json", action="store_true")

    status = subparsers.add_parser("status", help="Show canonical integrity manifest paths and current policy state.")
    status.add_argument("--root", type=_path, default=Path.cwd())
    status.add_argument("--policy", default=None, choices=["dev", "pre_release", "public_release", "runtime"])
    status.add_argument("--verbose", action="store_true")
    return parser


def command_rehash(args: argparse.Namespace) -> int:
    if args.developer_mode and args.release_mode and args.policy is None:
        print("Ambiguous integrity mode: --developer-mode and --release-mode were both provided. Use --policy dev, --policy pre_release, or --policy public_release.", file=sys.stderr)
        print('Example: python3.12 -m mac_audit_agent.integrity rehash --policy pre_release --author "Liquidsky Network Security" --reason "pre-release build" --build-id "$BUILD_ID" --sign-manifest', file=sys.stderr)
        return 2
    try:
        policy = normalize_policy(args.policy or ("public_release" if args.release_mode else "dev"))
        manifest, diff = rehash_manifest(
            args.root,
            author=args.author,
            reason=args.reason,
            manifest_path=args.manifest,
            signature_path=args.signature,
            build_id=args.build_id,
            release_id=args.release_id,
            developer_mode=args.developer_mode,
            require_clean_git=args.require_clean_git,
            sign=args.sign_manifest,
            private_key_path=args.private_key,
            public_key_path=args.public_key,
            release_mode=args.release_mode,
            audit_log=args.audit_log,
            policy=policy,
            legacy_output=args.legacy_output,
        )
    except Exception as exc:
        mapped = map_release_gate_exception(exc, integrity_status=resolve_integrity_status(args.policy or ("public_release" if args.release_mode else "dev"), root=args.root.resolve(strict=False)).status)
        try:
            write_audit_record(
                action="rehash",
                status="failed",
                root=args.root,
                audit_log=args.audit_log,
                author=args.author,
                reason=args.reason,
                details={"error": f"{type(exc).__name__}: {exc}", "release_gate_mapping": mapped.to_dict()},
            )
        except Exception:
            pass
        if mapped.failure_code == "RELEASE_GATE_DIRTY_SOURCE_TREE":
            print(f"release gate failed: {mapped.failure_code}: {mapped.message}", file=sys.stderr)
            print(f"integrity_status: {mapped.integrity_status}", file=sys.stderr)
            return 2
        print(f"rehash failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    root = args.root.resolve(strict=False)
    policy = normalize_policy(args.policy or ("public_release" if args.release_mode else "dev"))
    signature = resolve_signature_path(root, args.signature, manifest, policy=policy)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    checked_files = sum(1 for _ in manifest_files(payload))
    signed_payload = signed_payload_from_manifest(payload)
    excluded_files = len(signed_payload.get("excluded_runtime_scope") or [])
    post = _post_rehash_validation(
        root=root,
        policy=policy,
        manifest=manifest,
        signature=signature,
        sign_requested=args.sign_manifest,
        public_key=args.public_key,
        legacy_output=args.legacy_output,
    )
    print(f"policy: {policy}")
    print(f"manifest: {manifest}")
    print(f"signature: {signature}")
    print(f"checked files: {checked_files}")
    print(f"excluded files: {excluded_files}")
    print(f"release_id: {signed_payload.get('release_id', '')}")
    print(f"build_id: {signed_payload.get('build_id', '')}")
    print(f"git commit: {signed_payload.get('git_commit', '')}")
    print(f"trust state: {post['trust_state']}")
    for label in ("added", "modified", "removed"):
        values = diff[label]
        print(f"{label}: {len(values)}")
        for rel in values:
            print(f"  {rel}")
    print("Pre-UAT compatibility status: compatible" if post["pre_uat_compatible"] else "Pre-UAT compatibility status: not compatible")
    print("Post-Rehash Validation:")
    print(f"  status: {post['status']}")
    print(f"  pre_uat_compatible: {str(post['pre_uat_compatible']).lower()}")
    print(f"  manifest_path_used_by_pre_uat: {post['manifest_path_used_by_pre_uat']}")
    print(f"  manifest_path_written: {post['manifest_path_written']}")
    if post["mismatch_reason"]:
        print(f"  mismatch_reason: {post['mismatch_reason']}")
    print(f"next: python3.12 -m mac_audit_agent.integrity status --policy {policy} --verbose")
    if not post["pre_uat_compatible"] and not args.allow_post_verify_failure:
        return 1
    return 0


def _post_rehash_validation(
    *,
    root: Path,
    policy: str,
    manifest: Path,
    signature: Path,
    sign_requested: bool,
    public_key: Path | None,
    legacy_output: bool,
) -> dict[str, object]:
    paths = integrity_manifest_paths(root)
    pre_uat_manifest = paths.manifest_for_policy(policy)
    reasons: list[str] = []
    if legacy_output:
        reasons.append("Legacy manifest path updated. Pre-UAT does not validate this path. Run `integrity rehash --policy pre_release` or migrate the legacy manifest.")
    if manifest.resolve(strict=False) != pre_uat_manifest.resolve(strict=False):
        reasons.append("manifest path written differs from policy resolver path")
    if not manifest.exists():
        reasons.append("manifest missing after rehash")
    if sign_requested and not signature.exists():
        reasons.append("signature missing after signed rehash")
    summary = verify_manifest(
        root,
        manifest_path=manifest,
        signature_path=signature,
        public_key_path=public_key,
        require_signature=False,
        policy=policy,
    )
    strict_status = resolve_integrity_status(policy, root=root)
    if sign_requested:
        if strict_status.status != "verified":
            reasons.append(strict_status.reason or f"integrity verification returned {strict_status.result_code or strict_status.status}")
    elif not summary.ok:
        reasons.append(summary.to_dict().get("recommended_remediation", "manifest verification failed"))
    compatible = not reasons
    return {
        "status": "pass" if compatible else "fail",
        "trust_state": strict_status.trust_state,
        "pre_uat_compatible": compatible,
        "manifest_path_used_by_pre_uat": str(pre_uat_manifest),
        "manifest_path_written": str(manifest),
        "mismatch_reason": "; ".join(reasons),
    }


def command_verify(args: argparse.Namespace) -> int:
    if args.strict:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = resolve_integrity_status(args.policy, root=args.root.resolve(strict=False))
        if args.update_current_status:
            current = build_current_integrity_status(result, root=args.root.resolve(strict=False))
            write_current_integrity_status(current, root=args.root.resolve(strict=False))
            try:
                write_current_integrity_status_db(current)
            except Exception:
                pass
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"status: {result.status}")
            print(f"result_code: {result.result_code}")
            print(f"failure_code: {result.failure_code}")
            print(f"trust_state: {result.trust_state}")
            print(f"release_id: {result.release_id}")
            print(f"build_id: {result.build_id}")
            print(f"git_commit: {result.git_commit}")
            print(f"signing_key_fingerprint: {result.signing_key_fingerprint}")
            print(f"reason: {result.reason}")
            print(f"manifest: {result.manifest_path}")
            print(f"signature_bundle: {result.signature_path}")
            for rel in result.source_modified_files:
                print(f"HASH_MISMATCH: {rel}")
            for rel in result.missing_files:
                print(f"FILE_MISSING: {rel}")
            for rel in result.extra_files:
                print(f"UNEXPECTED_FILE: {rel}")
        return 0 if result.status == "verified" else 1
    summary = verify_manifest(
        args.root,
        manifest_path=args.manifest,
        signature_path=args.signature,
        public_key_path=args.public_key,
        require_signature=args.require_signature,
        policy=args.policy,
    )
    write_audit_record(
        action="verify",
        status="succeeded" if summary.ok else "failed",
        root=args.root,
        audit_log=args.audit_log,
        details=summary.to_dict(),
    )
    if args.json:
        print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"manifest: {resolve_manifest_path(args.root.resolve(strict=False), args.manifest, policy=args.policy)}")
        print(f"signature: {resolve_signature_path(args.root.resolve(strict=False), args.signature, args.manifest, policy=args.policy)}")
        print(f"status: {'verified' if summary.ok else 'attention_required'}")
        print(f"protected files verified: {summary.protected_files_verified}")
        print(f"modified: {len(summary.modified_files)} missing: {len(summary.missing_files)} unexpected: {len(summary.unexpected_files)}")
        for finding in [*summary.modified_files, *summary.missing_files, *summary.unexpected_files]:
            print(f"{finding.severity.upper()} {finding.status}: {finding.relative_path}")
            if finding.expected_hash:
                print(f"  expected: {finding.expected_hash}")
            if finding.observed_hash:
                print(f"  observed: {finding.observed_hash}")
            print(f"  action: {finding.recommended_action}")
        for error in [*summary.schema_errors, *summary.signature_errors]:
            print(f"ERROR: {error}")
        if summary.unsigned_manifest_warning:
            print("WARNING: integrity manifest is unsigned; sign it for tamper-evident release use.")
    return 0 if summary.ok else 1


def command_sign(args: argparse.Namespace) -> int:
    root = args.root.resolve(strict=False)
    policy = normalize_policy(args.policy)
    if args.require_yubikey_quorum:
        print("YubiKey quorum signing is optional legacy support and is no longer required. Use --developer-machine.", file=sys.stderr)
        return 2
    if not args.developer_machine:
        print("Signing requires --developer-machine so the trust model is explicit.", file=sys.stderr)
        return 2
    try:
        manifest, diff = rehash_manifest(
            root,
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            release_id=args.release_id,
            developer_mode=True,
            sign=False,
            audit_log=args.audit_log,
            policy=policy,
        )
    except Exception as exc:
        print(f"sign failed before developer-machine signing: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    try:
        bundle = sign_canonical_manifest(
            root=root,
            manifest_path=manifest,
            policy=policy,
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            release_id=args.release_id,
        )
    except DeveloperMachineSigningError as exc:
        print(f"Developer-machine signing failed: {exc}", file=sys.stderr)
        print(f"manifest: {manifest}", file=sys.stderr)
        print(f"signature bundle: {integrity_manifest_paths(root).canonical_signature_bundle}", file=sys.stderr)
        return 2
    result = resolve_integrity_status(policy, root=root)
    print(f"manifest: {manifest}")
    print(f"signature bundle: {bundle}")
    if result.signer_status:
        signer = result.signer_status[0]
        print(f"developer machine ID: {signer.get('developer_machine_id', '')}")
    print(f"added: {len(diff['added'])} modified: {len(diff['modified'])} removed: {len(diff['removed'])}")
    print(f"status: {result.status}")
    print(f"trust_state: {result.trust_state}")
    print(f"Pre-UAT compatibility: {str(result.pre_uat_compatible).lower()}")
    return 0 if result.status == "verified" else 1


def command_auto_sign(args: argparse.Namespace) -> int:
    try:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = auto_sign_integrity(
            args.root,
            policy=args.policy,
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            developer_machine=args.developer_machine,
            verify_pre_uat_compatible=args.verify_pre_uat_compatible,
            migrate_legacy=args.migrate_legacy,
            exclude_generated=args.exclude_generated,
            approve_current_source=args.approve_current_source,
            typed_confirmation=args.typed_confirmation,
            dry_run=args.dry_run,
            audit_log=args.audit_log,
        )
    except (AutoSignError, HeadlessIntegrityError) as exc:
        print(f"auto-sign failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"trust_state: {result.trust_state}")
        print(f"canonical_manifest_path: {result.canonical_manifest_path}")
        print(f"signature_path: {result.signature_path}")
        print(f"developer_machine_id: {result.developer_machine_id}")
        print(f"public_key_fingerprint: {result.public_key_fingerprint}")
        print(f"manifest_sha256: {result.manifest_sha256}")
        print(f"generated_artifacts_excluded: true")
        print(f"source_modified_files: {json.dumps(result.source_modified_files)}")
        print(f"generated_modified_files: {json.dumps(result.generated_modified_files)}")
        print(f"trust_metadata_files: {json.dumps(result.trust_metadata_files)}")
        print(f"legacy_ignored_files: {json.dumps(result.legacy_ignored_files)}")
        print(f"deprecated_artifacts: {json.dumps(result.deprecated_artifacts)}")
        print(f"pre_uat_compatible: {str(result.pre_uat_compatible).lower()}")
        print(f"pre_uat_checked_by_exact_function: {str(result.pre_uat_checked_by_exact_function).lower()}")
        print(f"pre_uat_check_ids: {json.dumps(result.pre_uat_check_ids)}")
        print(f"pre_uat_result_status: {result.pre_uat_result_status}")
        print(f"pre_uat_result_trust_state: {result.pre_uat_result_trust_state}")
        print(f"integrity_unknown: {str(result.integrity_unknown).lower()}")
        if result.consumer_comparison:
            print(f"consumer_comparison_status: {result.consumer_comparison.get('status', '')}")
            print(f"consumer_comparison_failure_code: {result.consumer_comparison.get('failure_code', '')}")
        print(f"evidence_path: {result.evidence_path}")
        if result.error:
            print(f"error: {result.error}")
        if result.recommended_action:
            print(f"recommended_action: {result.recommended_action}")
    return 0 if result.status == "verified" and not result.integrity_unknown else 1


def command_preflight(args: argparse.Namespace) -> int:
    try:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = run_integrity_preflight(args.policy, root=args.root.resolve(strict=False), strict=args.strict, approve_current_source=args.approve_current_source)
    except HeadlessIntegrityError as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"policy: {result.policy}")
        print(f"canonical_manifest_path: {result.canonical_manifest_path}")
        print(f"canonical_signature_path: {result.canonical_signature_path}")
        print(f"generated_exclusion_status: {result.generated_exclusion_status}")
        print(f"source_change_status: {result.source_change_status}")
        print(f"gui_import_status: {result.gui_import_status}")
        print(f"pre_uat_verifier_match: {str(result.pre_uat_verifier_match).lower()}")
        print(f"release_verifier_match: {str(result.release_verifier_match).lower()}")
        print(f"blocking_reasons: {json.dumps(result.blocking_reasons)}")
        print(f"failure_codes: {json.dumps(result.failure_codes)}")
        print(f"recommended_actions: {json.dumps(result.recommended_actions)}")
        print(f"recommended_command: {result.recommended_command}")
    return 0 if result.status == "pass" or (result.status == "warning" and not args.strict) else 1


def command_hash_scope(args: argparse.Namespace) -> int:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    result = build_hash_scope_report(args.root.resolve(strict=False), policy=args.policy)
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"included_files: {len(result.included_files)}")
        print(f"excluded_files: {len(result.excluded_files)}")
        print(f"generated_files: {len(result.generated_files)}")
        print(f"runtime_files: {len(result.runtime_files)}")
        print(f"build_files: {len(result.build_files)}")
        print(f"unknown_files: {len(result.unknown_files)}")
        print(f"dangerous_unclassified_files: {len(result.dangerous_unclassified_files)}")
        for rel in result.dangerous_unclassified_files:
            print(f"UNKNOWN_UNCLASSIFIED_ERROR: {rel}")
    return 0 if not result.dangerous_unclassified_files else 1


def command_independent_verify(args: argparse.Namespace) -> int:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    authority = resolve_integrity_status(args.policy, root=args.root.resolve(strict=False))
    result = run_independent_verify(args.policy, root=args.root.resolve(strict=False), authority_status=authority.status)
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.independent_status}")
        print(f"result_code: {result.result_code}")
        print(f"signature_valid: {str(result.independent_signature_valid).lower()}")
        print(f"file_match: {str(result.independent_file_match).lower()}")
        print(f"mismatch_with_authority: {str(result.mismatch_with_authority).lower()}")
        print(f"mismatches: {json.dumps(result.mismatches)}")
    return 0 if result.independent_status == "verified" and not result.mismatch_with_authority else 1


def command_runtime_sync_check(args: argparse.Namespace) -> int:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    result = run_runtime_sync_check(args.root.resolve(strict=False), policy=args.policy)
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"runtime_in_sync: {str(result.runtime_in_sync).lower()}")
        print(f"repo_package_path: {result.repo_package_path}")
        print(f"installed_runtime_path: {result.installed_runtime_path}")
        print(f"stale_runtime_paths: {json.dumps(result.stale_runtime_paths)}")
        print(f"recommended_fix: {result.recommended_fix}")
    return 0 if result.runtime_in_sync else 1


def command_compare_consumers(args: argparse.Namespace) -> int:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    result = compare_integrity_consumers(args.root.resolve(strict=False), policy=args.policy)
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"failure_code: {result.failure_code}")
        for consumer in result.consumers:
            print(f"{consumer.name}: status={consumer.status} trust_state={consumer.trust_state} failure_code={consumer.failure_code}")
        for mismatch in result.mismatches:
            print(f"MISMATCH: {mismatch}")
    return 0 if result.status == "pass" else 1


def command_reconcile_events(args: argparse.Namespace) -> int:
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    status = resolve_integrity_status(args.policy, root=args.root.resolve(strict=False))
    current = build_current_integrity_status(status, root=args.root.resolve(strict=False))
    db = SQLiteIntegrityEventStore(args.active_db) if args.active_db else None
    result = reconcile_integrity_events_after_verified_repair(current, db)
    ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"superseded_event_ids: {json.dumps(result.superseded_event_ids)}")
        print(f"active_event_ids: {json.dumps(result.active_event_ids)}")
        print(f"message: {result.message}")
    return 0 if result.status in {"reconciled", "no_event_store"} else 1


def command_cleanup_legacy(args: argparse.Namespace) -> int:
    result = cleanup_legacy_integrity(
        args.root.resolve(strict=False),
        dry_run=args.dry_run or not args.archive,
        archive=args.archive,
        confirm=args.confirm,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status in {"dry_run", "archived"} else 1


def command_cleanup_generated(args: argparse.Namespace) -> int:
    result = cleanup_generated(
        args.root.resolve(strict=False),
        egg_info=args.egg_info,
        dry_run=args.dry_run or not args.confirm,
        confirm=args.confirm,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status in {"dry_run", "removed"} else 1


def command_repair_and_sign(args: argparse.Namespace) -> int:
    try:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = repair_and_sign_integrity(
            args.root,
            policy=args.policy,
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            developer_machine=args.developer_machine,
            verify_pre_uat_compatible=args.verify_pre_uat_compatible,
            migrate_legacy=args.migrate_legacy,
            exclude_generated=args.exclude_generated,
            approve_current_source=args.approve_current_source,
            typed_confirmation=args.typed_confirmation,
            dry_run=args.dry_run,
            audit_log=args.audit_log,
        )
    except (AutoSignError, HeadlessIntegrityError) as exc:
        print(f"repair-and-sign failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"trust_state: {result.trust_state}")
        print(f"canonical_manifest_path: {result.canonical_manifest_path}")
        print(f"signature_path: {result.signature_path}")
        print(f"developer_machine_id: {result.developer_machine_id}")
        print(f"public_key_fingerprint: {result.public_key_fingerprint}")
        print(f"manifest_sha256: {result.manifest_sha256}")
        print(f"generated_artifacts_excluded: true")
        print(f"source_modified_files: {json.dumps(result.source_modified_files)}")
        print(f"generated_modified_files: {json.dumps(result.generated_modified_files)}")
        print(f"trust_metadata_files: {json.dumps(result.trust_metadata_files)}")
        print(f"legacy_ignored_files: {json.dumps(result.legacy_ignored_files)}")
        print(f"deprecated_artifacts: {json.dumps(result.deprecated_artifacts)}")
        print(f"pre_uat_compatible: {str(result.pre_uat_compatible).lower()}")
        print(f"pre_uat_checked_by_exact_function: {str(result.pre_uat_checked_by_exact_function).lower()}")
        print(f"pre_uat_check_ids: {json.dumps(result.pre_uat_check_ids)}")
        print(f"pre_uat_result_status: {result.pre_uat_result_status}")
        print(f"pre_uat_result_trust_state: {result.pre_uat_result_trust_state}")
        print(f"integrity_unknown: {str(result.integrity_unknown).lower()}")
        if result.consumer_comparison:
            print(f"consumer_comparison_status: {result.consumer_comparison.get('status', '')}")
            print(f"consumer_comparison_failure_code: {result.consumer_comparison.get('failure_code', '')}")
        print(f"evidence_path: {result.evidence_path}")
        if result.error:
            print(f"error: {result.error}")
        if result.recommended_action:
            print(f"recommended_action: {result.recommended_action}")
    return 0 if result.status == "verified" and not result.integrity_unknown else 1


def command_harden_and_validate(args: argparse.Namespace) -> int:
    try:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = harden_and_validate(
            args.root.resolve(strict=False),
            policy=args.policy,
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            developer_machine=args.developer_machine,
            exclude_generated=args.exclude_generated,
            migrate_legacy=args.migrate_legacy,
            verify_pre_uat_compatible=args.verify_pre_uat_compatible,
            approve_current_source=args.approve_current_source,
            typed_confirmation=args.typed_confirmation,
            run_independent=args.run_independent_verify,
            run_tamper_self_test=args.run_tamper_self_test,
        )
    except (HeadlessIntegrityError, AutoSignError) as exc:
        print(f"harden-and-validate failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"trust_state: {result.trust_state}")
        print(f"pre_uat_compatible: {str(result.pre_uat_compatible).lower()}")
        print(f"independent_verify: {result.independent_verify}")
        print(f"tamper_self_test: {result.tamper_self_test}")
        print(f"headless_safe: {str(result.headless_safe).lower()}")
        print(f"release_ready_integrity_gate: {result.release_ready_integrity_gate}")
        print(f"blocking_reasons: {json.dumps(result.blocking_reasons)}")
        print(f"evidence_dir: {result.evidence_dir}")
    return 0 if result.status == "verified" else 1


def command_discover(args: argparse.Namespace) -> int:
    result = discover_integrity_manifests(args.root.resolve(strict=False))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"canonical manifest: {result.canonical_path}")
        print(f"canonical exists: {str(result.canonical_exists).lower()}")
        print(f"recommended action: {result.recommended_action}")
        for candidate in result.discovered:
            if candidate.exists:
                label = "canonical" if candidate.canonical else "legacy"
                print(f"{label}: {candidate.path}")
    return 0 if result.recommended_action in {"use_canonical", "migrate_legacy", "rebuild_manifest"} else 1


def command_yubikey(args: argparse.Namespace) -> int:
    root = args.root.resolve(strict=False)
    if args.yubikey_command == "list":
        tokens = list_yubikey_tokens()
        print(json.dumps([token.to_dict() for token in tokens], indent=2, sort_keys=True))
        return 0 if tokens else 1
    if args.yubikey_command == "enroll":
        try:
            management_key = _resolve_cli_management_key(args)
            pin = _resolve_cli_pin(args)
            if management_key.is_default:
                print("Using default YubiKey PIV management key for enrollment.", file=sys.stderr)
            if sys.version_info >= (3, 14):
                print("Python 3.14 detected; YubiKey enrollment is running in CLI-only mode. Python 3.12 is recommended for enrollment.", file=sys.stderr)
            for line in get_yubikey_diagnostics().lines():
                print(line, file=sys.stderr)
            enrolled = enroll_yubikey(
                args.label,
                args.developer_id,
                args.slot,
                root=root,
                management_key=management_key,
                pin=pin,
                pin_policy=args.pin_policy,
                touch_policy=args.touch_policy,
            )
        except YubiKeySigningError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if management_key.is_default:
            print(DEFAULT_PIV_MANAGEMENT_KEY_WARNING, file=sys.stderr)
        print(json.dumps(asdict(enrolled), indent=2, sort_keys=True))
        return 0
    if args.yubikey_command == "verify":
        policy = load_trust_policy(root)
        active = policy.active_yubikeys()
        print(f"active enrolled YubiKeys: {len(active)}")
        print(f"required YubiKeys: {policy.required_count}")
        print(f"quorum: {'satisfied' if len(active) >= policy.required_count else 'missing'}")
        return 0 if len(active) >= policy.required_count else 1
    return 2


def command_machine(args: argparse.Namespace) -> int:
    root = args.root.resolve(strict=False)
    if args.machine_command == "enroll":
        try:
            identity = create_developer_machine_key(
                root,
                developer=args.developer,
                organization=args.organization,
                machine_label=args.machine_label,
                use_secure_enclave=args.use_secure_enclave,
            )
        except DeveloperMachineSigningError as exc:
            print(f"Developer-machine enrollment failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "developer_machine_id": identity.developer_machine_id,
            "developer": identity.developer_name,
            "organization": identity.organization,
            "machine_label": identity.machine_label,
            "public_key_fingerprint_sha256": identity.public_key_fingerprint_sha256,
            "secure_enclave_backed": identity.secure_enclave_backed,
            "keychain_backed": identity.keychain_backed,
            "trust_status": identity.trust_status,
            "limitations": identity.limitations,
        }, indent=2, sort_keys=True))
        return 0
    if args.machine_command == "status":
        registry = load_trusted_developer_machines(root)
        print(json.dumps(registry.to_dict(), indent=2, sort_keys=True))
        return 0 if registry.active_machines() else 1
    if args.machine_command == "revoke":
        machine = revoke_developer_machine(root, args.developer_machine_id, args.reason)
        if machine is None:
            print("Developer machine was not found.", file=sys.stderr)
            return 1
        print(json.dumps(machine.to_dict(), indent=2, sort_keys=True))
        return 0
    return 2


def _resolve_cli_management_key(args: argparse.Namespace) -> ManagementKey:
    if args.management_key and args.prompt_management_key:
        raise ManagementKeyInputError("Ambiguous management key input. Use --management-key default, --management-key hex:<HEX>, or --prompt-management-key.")
    if args.management_key is not None:
        return parse_management_key_input(args.management_key)
    value = getpass.getpass("Enter a management key [blank to use default key]: ")
    return parse_management_key_input(value)


def _resolve_cli_pin(args: argparse.Namespace) -> str | None:
    if args.pin is not None and args.prompt_pin:
        raise YubiKeySigningError("Ambiguous PIN input. Use --pin or --prompt-pin, not both.")
    if args.prompt_pin:
        return getpass.getpass("Enter PIV PIN: ")
    return args.pin


def command_codex_provenance(args: argparse.Namespace) -> int:
    if args.codex_command != "create":
        return 2
    path = create_codex_provenance(args.root, operator=args.operator, summary=args.summary, approved_change_id=args.approved_change_id, notes=args.notes)
    print(f"codex provenance record: {path}")
    print("codex identity verification: metadata_only")
    print("cryptographic trust: developer-machine signature required")
    return 0


def command_repair_status(args: argparse.Namespace) -> int:
    root = args.root.resolve(strict=False)
    discovery = discover_integrity_manifests(root)
    result = resolve_integrity_status(args.policy, root=root)
    print(f"canonical manifest: {discovery.canonical_path}")
    print(f"discovery action: {discovery.recommended_action}")
    print(f"trust_state: {result.trust_state}")
    print(f"recommended_action: {result.recommended_action}")
    if args.require_yubikey_quorum:
        print("YubiKey quorum is optional legacy support and is no longer required.", file=sys.stderr)
        return 2
    if args.developer_machine and result.status != "verified":
        print("next: python3.12 -m mac_audit_agent.integrity machine enroll --developer \"Liquidsky Network Security\" --organization \"Liquidsky Network Security\" --machine-label \"Liquidsky Primary Dev Mac\"", file=sys.stderr)
    return 0 if result.status in {"verified", "warning"} else 1


def command_doctor(args: argparse.Namespace) -> int:
    status = build_integrity_doctor_status(
        args.root,
        manifest_path=args.manifest,
        signature_path=args.signature,
        public_key_path=args.public_key,
        require_signature=args.require_signature,
        policy=args.policy,
    )
    if args.json:
        print(json.dumps(status, indent=2, sort_keys=True))
    else:
        print(f"policy: {status['policy']}")
        print(f"canonical manifest: {status['canonical_manifest_path']}")
        print(f"canonical signature: {status['canonical_signature_path']}")
        print(f"manifest path: {status['canonical_manifest_path']}")
        print(f"manifest exists: {str(status['canonical_manifest_exists']).lower()}")
        print(f"public key source: {status.get('public_key_source', '')}")
        print(f"public key fingerprint: {status.get('public_key_fingerprint', '')}")
        print(f"private key required for verify: {str(status.get('private_key_required_for_verify', False)).lower()}")
        print(f"signing algorithm: {status.get('signing_algorithm', '')}")
        print(f"signature present: {str(status.get('signature_present', status['canonical_signature_exists'])).lower()}")
        print(f"signature valid: {str(status.get('signature_valid', False)).lower()}")
        print(f"hash algorithm: {status.get('hash_algorithm', '')}")
        print(f"tracked file count: {status['source_files_checked_count']}")
        print(f"excluded file count: {status.get('excluded_files_count', 0)}")
        print(f"release_id: {status.get('release_id', '')}")
        print(f"build_id: {status.get('build_id', '')}")
        print(f"git commit: {status.get('git_commit', '')}")
        print(f"current integrity result: {status.get('current_integrity_result', status.get('result_code', ''))}")
        print(f"signature exists: {'yes' if status['canonical_signature_exists'] else 'no'}")
        print(f"signature status: {status['signature_status']}")
        print(f"result_code: {status.get('result_code', '')}")
        print(f"failure_code: {status.get('failure_code', '')}")
        print(f"trust_state: {status['trust_state']}")
        print(f"status: {status['status']}")
        print(f"source files checked: {status['source_files_checked_count']}")
        print(f"excluded files count: {status.get('excluded_files_count', 0)}")
        print(f"modified source files: {len(status['modified_source_files'])}")
        print(f"modified generated files: {len(status['modified_generated_files'])}")
        print(f"path consistency: {json.dumps(status['path_consistency'], sort_keys=True)}")
        print(f"headless safe: {str(status['headless_safe']).lower()}")
        print(f"exact failure reason: {status.get('exact_failure_reason', '')}")
        print(f"suggested fix: {status.get('suggested_fix', '')}")
        print("exact remediation steps:")
        for step in status.get("exact_remediation_steps", []):
            print(f"  - {step}")
        print(f"recommended repair: {status['recommended_repair_command']}")
    consistent = all(status.get("path_consistency", {}).values())
    return 0 if status["status"] == "verified" and consistent and status.get("headless_safe") else 1


def command_release_verify(args: argparse.Namespace) -> int:
    policy = normalize_policy(args.policy)
    root = args.root.resolve(strict=False)
    manifest = resolve_manifest_path(root, args.manifest, policy=policy)
    signature = resolve_signature_path(root, args.signature, manifest, policy=policy)
    result = verify_release(
        root,
        mode=policy,
        manifest_path=manifest,
        signature_path=signature,
        public_key=args.public_key,
        artifact_manifest=args.artifact_manifest,
        artifact_signature=args.artifact_signature,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.status in {"verified", "non_applicable_for_policy", "warning"} and policy == "dev" else 0 if result.status == "verified" else 1


def command_public_release_gate(args: argparse.Namespace) -> int:
    try:
        ensure_integrity_cli_headless_safe(strict_loaded_modules=True)
        result = run_public_release_gate(
            args.root.resolve(strict=False),
            author=args.author,
            reason=args.reason,
            build_id=args.build_id,
            developer_machine=args.developer_machine,
            run_build=args.build,
            run_tests=args.test,
            run_twine_check=args.twine_check,
            run_clean_install=args.clean_install,
            sign_artifacts=args.sign_artifacts,
            verify_all=args.verify_all,
        )
    except (HeadlessIntegrityError, DeveloperMachineSigningError) as exc:
        print(f"public-release-gate failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"status: {result.status}")
        print(f"source_integrity_status: {result.source_integrity_status}")
        print(f"source_signature_status: {result.source_signature_status}")
        print(f"artifact_integrity_status: {result.artifact_integrity_status}")
        print(f"pytest_status: {result.pytest_status}")
        print(f"build_status: {result.build_status}")
        print(f"twine_status: {result.twine_status}")
        print(f"clean_install_status: {result.clean_install_status}")
        print(f"runtime_artifact_hygiene_status: {result.runtime_artifact_hygiene_status}")
        print(f"release_ready_for_public_distribution: {str(result.release_ready_for_public_distribution).lower()}")
        print(f"blocking_checks: {json.dumps(result.blocking_checks)}")
        print(f"recommended_actions: {json.dumps(result.recommended_actions)}")
        print(f"evidence_path: {result.evidence_path}")
    return 0 if result.release_ready_for_public_distribution else 1


def command_status(args: argparse.Namespace) -> int:
    policy_source = "explicit CLI" if args.policy else "dev default"
    policy = normalize_policy(args.policy or "dev")
    root = args.root.resolve(strict=False)
    paths = integrity_manifest_paths(root)
    selected_manifest = paths.manifest_for_policy(policy)
    selected_signature = paths.signature_for_policy(policy)
    resolved = resolve_integrity_status(policy, root=root)
    payload = {}
    if selected_manifest.exists():
        try:
            payload = json.loads(selected_manifest.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
    legacy_present = any(path.exists() for path in paths.legacy_manifest_paths)
    print(f"selected policy: {policy}")
    print(f"effective policy source: {policy_source}")
    print(f"canonical manifest path: {selected_manifest}")
    print(f"signature bundle path: {selected_signature}")
    print(f"canonical trust policy: {paths.canonical_trust_policy}")
    print(f"canonical dev manifest: {paths.canonical_manifest}")
    print(f"canonical release manifest: {paths.canonical_manifest}")
    print(f"currently selected manifest: {selected_manifest}")
    print(f"manifest exists: {'yes' if resolved.manifest_exists else 'no'}")
    print(f"signature exists: {'yes' if resolved.signature_exists else 'no'}")
    print(f"signature valid: {'yes' if resolved.signature_valid is True else 'no' if resolved.signature_valid is False else 'not checked'}")
    print(f"Pre-UAT policy {policy} will validate {selected_manifest}: yes")
    print(f"Integrity Health reads this manifest: {'yes' if resolved.manifest_path == str(selected_manifest) else 'no'}")
    print(f"legacy manifest present: {'yes - Legacy manifest present but ignored.' if legacy_present else 'no'}")
    print(f"legacy manifest ignored: {'yes' if legacy_present else 'not applicable'}")
    print(f"trust_state: {resolved.trust_state}")
    print(f"status: {resolved.status}")
    print(f"result_code: {resolved.result_code}")
    print(f"failure_code: {resolved.failure_code}")
    print(f"reason: {resolved.reason}")
    print(f"recommended_action: {resolved.recommended_action}")
    if args.verbose:
        print(f"last signed at: {payload.get('generated_at') or payload.get('created_at', '')}")
        print(f"last author: {payload.get('author') or payload.get('signed_by', '')}")
        print(f"last reason: {payload.get('reason', '')}")
        print(f"release ID: {resolved.release_id}")
        print(f"build ID: {resolved.build_id or payload.get('build_id', '')}")
        print(f"git commit: {resolved.git_commit or payload.get('git_commit', '')}")
        print(f"signing key fingerprint: {resolved.signing_key_fingerprint}")
        print(f"checked files: {resolved.checked_files}")
        print(f"excluded files: {len(resolved.excluded_files)}")
        print(f"modified files: {len(resolved.modified_files)}")
        print(f"generated modified files: {len(resolved.generated_modified_files)}")
        print(f"source modified files: {len(resolved.source_modified_files)}")
        print(f"signature bundle status: {resolved.quorum_status or 'not checked'}")
        print(f"signer status: {json.dumps(resolved.signer_status, sort_keys=True)}")
        print(f"added files: {len(resolved.extra_files)}")
        print(f"removed files: {len(resolved.missing_files)}")
    print(f"next command: python3.12 -m mac_audit_agent.integrity verify --policy {policy} --strict")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rehash":
        return command_rehash(args)
    if args.command == "verify":
        return command_verify(args)
    if args.command == "sign":
        return command_sign(args)
    if args.command == "auto-sign":
        return command_auto_sign(args)
    if args.command == "preflight":
        return command_preflight(args)
    if args.command == "hash-scope":
        return command_hash_scope(args)
    if args.command == "independent-verify":
        return command_independent_verify(args)
    if args.command == "runtime-sync-check":
        return command_runtime_sync_check(args)
    if args.command == "compare-consumers":
        return command_compare_consumers(args)
    if args.command == "cleanup-legacy":
        return command_cleanup_legacy(args)
    if args.command == "cleanup-generated":
        return command_cleanup_generated(args)
    if args.command == "reconcile-events":
        return command_reconcile_events(args)
    if args.command == "repair-and-sign":
        return command_repair_and_sign(args)
    if args.command == "harden-and-validate":
        return command_harden_and_validate(args)
    if args.command == "discover":
        return command_discover(args)
    if args.command == "yubikey":
        return command_yubikey(args)
    if args.command == "machine":
        return command_machine(args)
    if args.command == "codex-provenance":
        return command_codex_provenance(args)
    if args.command == "repair-status":
        return command_repair_status(args)
    if args.command == "doctor":
        return command_doctor(args)
    if args.command == "release_verify":
        return command_release_verify(args)
    if args.command == "public-release-gate":
        return command_public_release_gate(args)
    if args.command == "status":
        return command_status(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

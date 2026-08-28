from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import json
import os
import uuid
from pathlib import Path


def _darwin_yara_crypto_override() -> Path | None:
    """Return Python's OpenSSL libcrypto when a YARA wheel vendors a conflicting copy."""
    if sys.platform != "darwin":
        return None
    yara_spec = importlib.util.find_spec("yara")
    if yara_spec is None or not yara_spec.origin:
        return None
    vendored_crypto = Path(yara_spec.origin).parent / "yara_python.dylibs" / "libcrypto.3.dylib"
    if not vendored_crypto.is_file():
        return None
    try:
        import _ssl

        linked_libraries = subprocess.run(
            ["otool", "-L", str(_ssl.__file__)],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout
    except (ImportError, OSError, subprocess.SubprocessError):
        return None
    for line in linked_libraries.splitlines()[1:]:
        candidate = Path(line.strip().split(" (compatibility", 1)[0])
        if candidate.name == "libcrypto.3.dylib" and candidate.is_file():
            return candidate
    return None


def _finalize_macos_bundle(app_path: Path, *, build_id: str, entitlements: str = "") -> bool:
    """Install the bundle hash inventory and restore the outer code signature."""
    if sys.platform != "darwin":
        return True
    contents = app_path / "Contents"
    if not contents.is_dir():
        print(f"Expected macOS application bundle was not produced: {app_path}", file=sys.stderr)
        return False
    from mac_audit_agent.integrity.bundle_integrity import (
        verify_bundle_integrity,
        write_bundle_integrity_manifest,
    )

    manifest = write_bundle_integrity_manifest(contents, build_id=build_id)
    identity = os.environ.get("MSAA_CODESIGN_IDENTITY") or "-"
    command = ["/usr/bin/codesign", "--force", "--sign", identity]
    if entitlements and Path(entitlements).is_file():
        command.extend(["--entitlements", entitlements])
    command.append(str(app_path))
    signed = subprocess.run(command, capture_output=True, text=True, check=False)
    if signed.returncode != 0:
        print(signed.stderr or signed.stdout or "codesign failed", file=sys.stderr)
        return False
    verification = verify_bundle_integrity(contents)
    if verification.status != "verified":
        print(json.dumps(verification.to_dict(), indent=2, sort_keys=True), file=sys.stderr)
        return False
    print(f"Bundle SHA-256 manifest: {manifest}")
    print(f"Bundle files verified: {verification.checked_files}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a native MSAA PyInstaller application on the current platform.")
    parser.add_argument("--format", choices=("onedir", "onefile"), default="onedir")
    parser.add_argument("--clean", action="store_true", help="Remove PyInstaller analysis cache before building.")
    parser.add_argument("--distpath", type=Path, help="Override the output directory (useful for isolated measurements).")
    parser.add_argument("--workpath", type=Path, help="Override the temporary analysis directory.")
    parser.add_argument("--experimental-runtime", action="store_true", help="Permit a candidate runtime while retaining experimental classification.")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from mac_audit_agent.runtime.packaging_compatibility import build_manifest, preflight
    policy, failures = preflight(root, allow_experimental=args.experimental_runtime)
    if failures:
        print("\n\n".join(failures), file=sys.stderr)
        return 2
    missing_desktop = [name for name in ("PySide6", "docx", "openpyxl", "yaml") if importlib.util.find_spec(name) is None]
    if missing_desktop:
        print(
            "Desktop build dependencies are incomplete: %s. Run: %r -m pip install '.[desktop,build]'"
            % (", ".join(missing_desktop), sys.executable),
            file=sys.stderr,
        )
        return 2
    if args.format == "onedir":
        command = [sys.executable, "-m", "PyInstaller", "Mac Audit Agent.spec", "--noconfirm"]
        if args.clean:
            command.append("--clean")
    else:
        separator = ";" if sys.platform == "win32" else ":"
        generated_spec_dir = args.workpath or (root / "build" / "pyinstaller-specs")
        generated_spec_dir.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--windowed",
            "--onefile",
            "--name",
            "Mac Audit Agent",
            "--specpath",
            str(generated_spec_dir),
            "--icon",
            str(root / "mac_audit_agent/assets/app_icon.icns"),
            "--add-data",
            f"{root / 'mac_audit_agent/assets'}{separator}mac_audit_agent/assets",
            "--add-data",
            f"{root / 'mac_audit_agent/integrity/trust'}{separator}mac_audit_agent/integrity/trust",
            "--add-data",
            f"{root / 'mac_audit_agent/help/resources'}{separator}mac_audit_agent/help/resources",
            "--add-data",
            f"{root / 'mac_audit_agent/anti_typosquatting/data_manifest.json'}{separator}mac_audit_agent/anti_typosquatting",
            "--add-data",
            f"{root / 'mac_audit_agent/frameworks.py'}{separator}mac_audit_agent",
            "--hidden-import",
            "mac_audit_agent.integrity.__main__",
            "--hidden-import",
            "docx",
            "--hidden-import",
            "openpyxl",
            "--copy-metadata",
            "PySide6",
            "--copy-metadata",
            "shiboken6",
            "--copy-metadata",
            "openpyxl",
            "--copy-metadata",
            "python-docx",
            "--copy-metadata",
            "PyYAML",
            str(root / "launcher.py"),
        ]
        yara_crypto_override = _darwin_yara_crypto_override()
        if yara_crypto_override is not None:
            command.extend(
                [
                    "--add-binary",
                    f"{yara_crypto_override}{separator}yara_python.dylibs",
                ]
            )
            print(f"Using Python-compatible OpenSSL for bundled YARA: {yara_crypto_override}")
        for resource in (
            "integrity_manifest.json",
            "integrity_manifest.signature.json",
            "trust_policy.json",
        ):
            source = f"mac_audit_agent/integrity/{resource}"
            if (root / source).is_file():
                command.extend(["--add-data", f"{root / source}{separator}mac_audit_agent/integrity"])
        if args.clean:
            command.append("--clean")
    if args.distpath:
        command.extend(["--distpath", str(args.distpath)])
    if args.workpath:
        command.extend(["--workpath", str(args.workpath)])
    manifest_dir = args.workpath or (root / "build" / "packaging-metadata")
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "msaa_build_manifest.json"
    build_metadata = build_manifest(root, policy, build_id=uuid.uuid4().hex)
    manifest_path.write_text(json.dumps(build_metadata, indent=2, sort_keys=True), encoding="utf-8")
    if args.format == "onefile":
        separator = ";" if sys.platform == "win32" else ":"
        command.extend(["--add-data", f"{manifest_path}{separator}mac_audit_agent"])
    environment = dict(os.environ, MSAA_BUILD_MANIFEST=str(manifest_path))
    print(f"Packaging runtime classification: {policy.classification}")
    print(f"Build manifest: {manifest_path}")
    print("Building on the current OS/architecture; PyInstaller does not cross-compile.")
    print("Command:", subprocess.list2cmdline(command))
    completed = subprocess.run(command, cwd=root, env=environment, check=False)
    if completed.returncode != 0:
        return completed.returncode
    if sys.platform == "darwin":
        dist_root = args.distpath or (root / "dist")
        app_path = Path(dist_root) / "Mac Audit Agent.app"
        if not _finalize_macos_bundle(
            app_path,
            build_id=str(build_metadata.get("build_id", "")),
            entitlements=os.environ.get("MSAA_APP_ENTITLEMENTS", ""),
        ):
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

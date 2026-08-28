from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mac_audit_agent.build_identity import detect_build_identity


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b""): digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str:
    try: return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError): return ""


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description="Generate unsigned release manifest, checksums, SBOM and provenance without modifying integrity baselines.")
    parser.add_argument("--dist", type=Path, default=Path("dist")); parser.add_argument("--architecture", choices=("arm64","x86_64","universal2","python"), required=True)
    args=parser.parse_args(argv); root=Path(__file__).resolve().parents[1]; dist=(root/args.dist).resolve() if not args.dist.is_absolute() else args.dist
    dist.mkdir(parents=True,exist_ok=True)
    excluded={"SHA256SUMS","release-manifest.json","SBOM.cyclonedx.json","provenance.json"}
    artifacts=[path for path in sorted(dist.rglob("*")) if path.is_file() and path.name not in excluded and not path.name.endswith(".sig")]
    entries=[{"path":str(path.relative_to(dist)),"size":path.stat().st_size,"sha256":_sha256(path),"declared_architecture":args.architecture} for path in artifacts]
    identity=detect_build_identity(root).to_dict(); timestamp=datetime.now(timezone.utc).isoformat()
    manifest={"schema_version":"1.0","product":"MSAA","version":identity["app_version"],"release_id":os.environ.get("MSAA_RELEASE_ID",identity["build_id"]),"build_id":os.environ.get("MSAA_BUILD_ID",identity["build_id"]),"git_commit":_git(root,"rev-parse","HEAD") or "unknown","dirty_tree":bool(_git(root,"status","--porcelain")),"timestamp":timestamp,"architecture":args.architecture,"deployment_target":os.environ.get("MACOSX_DEPLOYMENT_TARGET","12.0"),"python_version":platform.python_version(),"build_tool":os.environ.get("MSAA_BUILD_TOOL","setuptools/PyInstaller"),"signing_state":os.environ.get("MSAA_SIGNING_STATE","unsigned"),"notarization_state":os.environ.get("MSAA_NOTARIZATION_STATE","not_submitted"),"artifacts":entries}
    (dist/"release-manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    (dist/"SHA256SUMS").write_text("".join(f"{item['sha256']}  {item['path']}\n" for item in entries),encoding="utf-8")
    components=[{"type":"file","name":item["path"],"hashes":[{"alg":"SHA-256","content":item["sha256"]}]} for item in entries]
    (dist/"SBOM.cyclonedx.json").write_text(json.dumps({"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"timestamp":timestamp,"component":{"type":"application","name":"MSAA","version":identity["app_version"]}},"components":components},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    (dist/"provenance.json").write_text(json.dumps({"predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":item["path"],"digest":{"sha256":item["sha256"]}} for item in entries],"buildDefinition":{"buildType":"https://github.com/fuzzlove/macOS-Security-Audit-Agent","externalParameters":{"architecture":args.architecture}},"runDetails":{"builder":{"id":os.environ.get("GITHUB_WORKFLOW_REF","local")},"metadata":{"invocationId":os.environ.get("GITHUB_RUN_ID","local")}}},indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"artifacts":len(entries),"dist":str(dist),"manifest_sha256":_sha256(dist/"release-manifest.json")},sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT=Path(__file__).parents[1]


def test_pyproject_has_universal_cli_entry_points() -> None:
    try:
        import tomllib
    except ImportError:
        from mac_audit_agent.compat import tomllib
    project=tomllib.loads((ROOT/"pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert {"msaa","msaa-doctor","msaa-cli","msaa-integrity"} <= set(project["scripts"])
    assert not project["dependencies"]
    assert {"gui","network","forensics","development","build","test","all"} <= set(project["optional-dependencies"])


def test_release_scripts_refuse_architecture_mislabeling() -> None:
    universal=(ROOT/"scripts/build-universal.sh").read_text(encoding="utf-8")
    verify=(ROOT/"scripts/verify-architectures.sh").read_text(encoding="utf-8")
    assert "Universal2 build refused" in universal
    assert "single-architecture Mach-O in universal2 artifact" in verify
    assert "lipo -archs" in universal and "lipo -archs" in verify


def test_release_evidence_is_hash_backed(tmp_path: Path) -> None:
    (tmp_path/"MSAA-test-macOS-arm64.zip").write_bytes(b"safe fixture")
    result=subprocess.run([sys.executable,str(ROOT/"scripts/generate_release_evidence.py"),"--dist",str(tmp_path),"--architecture","arm64"],cwd=ROOT,capture_output=True,text=True,timeout=30,check=False)
    assert result.returncode == 0, result.stderr
    manifest=json.loads((tmp_path/"release-manifest.json").read_text())
    assert manifest["architecture"] == "arm64" and manifest["artifacts"][0]["sha256"]
    assert (tmp_path/"SHA256SUMS").is_file() and (tmp_path/"SBOM.cyclonedx.json").is_file() and (tmp_path/"provenance.json").is_file()

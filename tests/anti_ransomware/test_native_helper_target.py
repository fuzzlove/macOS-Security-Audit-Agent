import platform
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/"native/containment_helper"


def test_helper_source_has_exact_ids_peer_requirement_and_no_action_api():
    source=(HELPER/"main.c").read_text(encoding="utf-8")
    assert 'com.fuzzlove.MacAuditAgent.ContainmentHelper.xpc' in source
    assert "xpc_listener_set_peer_code_signing_requirement" in source
    assert "production_actions_enabled\",false" in source
    for forbidden in ("kill_pid", "send_signal", "run_command", "system(", "popen("):
        assert forbidden not in source


@pytest.mark.skipif(platform.system()!="Darwin" or shutil.which("xcrun") is None,reason="macOS compiler required")
def test_native_helper_builds_arm64_and_self_check_is_fail_closed(tmp_path):
    artifact=tmp_path/"MSAAContainmentHelper"
    result=subprocess.run(["sh",str(HELPER/"build.sh"),str(artifact)],cwd=ROOT,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert '"native":true' in result.stdout and '"production_actions_enabled":false' in result.stdout
    description=subprocess.run(["file",str(artifact)],capture_output=True,text=True,check=True).stdout
    assert "Mach-O 64-bit executable arm64" in description

from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_endpoint_security_entitlements_are_sensor_only_and_least_privilege():
    entitlement_path = ROOT / "native/anti_ransomware_sensor/AntiRansomwareSensor.entitlements"
    with entitlement_path.open("rb") as handle:
        entitlements = plistlib.load(handle)
    assert entitlements == {"com.apple.developer.endpoint-security.client": True}


def test_sensor_bundle_metadata_matches_production_identifier():
    info_path = ROOT / "native/anti_ransomware_sensor/Info.plist"
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    assert info["CFBundleExecutable"] == "MSAAEndpointSecuritySensor"
    assert info["CFBundleIdentifier"] == "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor"
    assert info["CFBundlePackageType"] == "APPL"
    assert info["LSBackgroundOnly"] is True


def test_release_signing_fails_closed_without_approved_profile():
    env = os.environ.copy()
    env.update(
        {
            "MSAA_TEAM_ID": "ABCDEFGHIJ",
            "MSAA_DEVELOPER_ID_APPLICATION_IDENTITY": "Apple Development: Test (ABCDEFGHIJ)",
        }
    )
    env.pop("MSAA_PROVISIONING_PROFILE", None)
    result = subprocess.run(
        ["/bin/sh", str(ROOT / "scripts/sign_active_containment_release.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "MSAA_PROVISIONING_PROFILE" in result.stderr


def test_signing_scripts_do_not_use_deep_signing():
    for relative_path in (
        "scripts/sign_active_containment_release.sh",
        "scripts/verify_endpoint_security_signature.sh",
    ):
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        assert "codesign --force --deep" not in source
        assert "codesign --deep --force" not in source

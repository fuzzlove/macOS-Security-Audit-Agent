from __future__ import annotations

from datetime import datetime, timedelta, timezone

from scripts.create_endpoint_security_profile import (
    AutomationError,
    profile_request_payload,
    verify_profile_payload,
)


TEAM = "ABCDEFGHIJ"
BUNDLE = "com.example.EndpointSecuritySensor"
CERTIFICATE = b"certificate-der"


def test_development_profile_request_includes_registered_mac():
    payload = profile_request_payload(
        name="Development",
        profile_type="MAC_APP_DEVELOPMENT",
        bundle_resource_id="bundle-1",
        certificate_resource_id="cert-1",
        device_resource_ids=["device-1"],
    )
    relationships = payload["data"]["relationships"]
    assert relationships["bundleId"]["data"]["id"] == "bundle-1"
    assert relationships["certificates"]["data"][0]["id"] == "cert-1"
    assert relationships["devices"]["data"][0]["id"] == "device-1"


def test_developer_id_profile_request_omits_devices():
    payload = profile_request_payload(
        name="Distribution",
        profile_type="MAC_APP_DIRECT",
        bundle_resource_id="bundle-1",
        certificate_resource_id="cert-1",
        device_resource_ids=[],
    )
    assert "devices" not in payload["data"]["relationships"]


def test_profile_verification_requires_endpoint_security_entitlement():
    profile = {
        "TeamIdentifier": [TEAM],
        "DeveloperCertificates": [CERTIFICATE],
        "ExpirationDate": datetime.now(timezone.utc) + timedelta(days=1),
        "Entitlements": {
            "com.apple.application-identifier": f"{TEAM}.{BUNDLE}",
            "com.apple.developer.team-identifier": TEAM,
        },
    }
    try:
        verify_profile_payload(profile, team_id=TEAM, bundle_id=BUNDLE, certificate_der=CERTIFICATE)
    except AutomationError as exc:
        assert "endpoint-security.client" in str(exc)
    else:
        raise AssertionError("profile without Endpoint Security entitlement was accepted")


def test_profile_verification_accepts_exact_approved_contract():
    expiration = datetime.now(timezone.utc) + timedelta(days=1)
    profile = {
        "UUID": "profile-uuid",
        "Name": "MSAA Endpoint Security",
        "TeamIdentifier": [TEAM],
        "DeveloperCertificates": [CERTIFICATE],
        "ExpirationDate": expiration,
        "Entitlements": {
            "com.apple.application-identifier": f"{TEAM}.{BUNDLE}",
            "com.apple.developer.team-identifier": TEAM,
            "com.apple.developer.endpoint-security.client": True,
        },
    }
    result = verify_profile_payload(profile, team_id=TEAM, bundle_id=BUNDLE, certificate_der=CERTIFICATE)
    assert result["uuid"] == "profile-uuid"
    assert result["application_identifier"] == f"{TEAM}.{BUNDLE}"

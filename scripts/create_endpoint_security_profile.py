#!/usr/bin/env python3
"""Create and verify an MSAA Endpoint Security provisioning profile.

The managed Endpoint Security capability must already be approved and enabled
for the explicit App ID. This script intentionally does not try to alter that
approval. It uses an App Store Connect API key to create and download either a
Mac development profile or a Developer ID profile.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


API_BASE = "https://api.appstoreconnect.apple.com/v1"
DEFAULT_BUNDLE_ID = "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor"
DEFAULT_TEAM_ID = "QPWZZT9ZZK"
PROFILE_TYPES = {
    "development": "MAC_APP_DEVELOPMENT",
    "developer-id": "MAC_APP_DIRECT",
}


class AutomationError(RuntimeError):
    pass


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _load_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography import x509
    except ImportError as exc:
        raise AutomationError(
            "The cryptography package is required. Install the project's crypto extra first."
        ) from exc
    return hashes, serialization, ec, decode_dss_signature, x509


def create_jwt(key_id: str, issuer_id: str, private_key_path: Path, now: int | None = None) -> str:
    hashes, serialization, ec, decode_dss_signature, _ = _load_crypto()
    info = private_key_path.stat()
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise AutomationError(
            f"API private key permissions are too broad: {private_key_path}; run chmod 600 on it."
        )
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise AutomationError("App Store Connect API key is not an EC private key.")
    issued_at = int(time.time() if now is None else now)
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    claims = {
        "iss": issuer_id,
        "iat": issued_at,
        "exp": issued_at + 15 * 60,
        "aud": "appstoreconnect-v1",
    }
    signing_input = ".".join(
        _b64url(json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        for item in (header, claims)
    )
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    return f"{signing_input}.{_b64url(signature)}"


@dataclass
class AppStoreConnectClient:
    key_id: str
    issuer_id: str
    private_key_path: Path
    timeout: int = 30

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{API_BASE}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {create_jwt(self.key_id, self.issuer_id, self.private_key_path)}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                errors = json.loads(raw).get("errors", [])
                detail = "; ".join(str(item.get("detail") or item.get("title")) for item in errors)
            except (ValueError, AttributeError):
                detail = raw[:500]
            raise AutomationError(f"Apple API request failed ({exc.code}): {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise AutomationError(f"Apple API connection failed: {exc.reason}") from exc


def _single_resource(response: dict[str, Any], description: str) -> dict[str, Any]:
    resources = response.get("data", [])
    if len(resources) != 1:
        raise AutomationError(f"Expected exactly one {description}; found {len(resources)}.")
    return resources[0]


def local_certificate_der(path: Path) -> bytes:
    _, serialization, _, _, x509 = _load_crypto()
    raw = path.read_bytes()
    try:
        certificate = x509.load_der_x509_certificate(raw)
    except ValueError:
        certificate = x509.load_pem_x509_certificate(raw)
    return certificate.public_bytes(serialization.Encoding.DER)


def resolve_bundle(client: AppStoreConnectClient, bundle_id: str) -> dict[str, Any]:
    response = client.request(
        "GET",
        "/bundleIds",
        query={"filter[identifier]": bundle_id, "limit": "200"},
    )
    return _single_resource(response, f"registered bundle ID {bundle_id}")


def resolve_certificate(client: AppStoreConnectClient, certificate_der: bytes) -> dict[str, Any]:
    response = client.request(
        "GET",
        "/certificates",
        query={
            "fields[certificates]": "name,certificateType,displayName,serialNumber,platform,expirationDate,certificateContent,activated",
            "limit": "200",
        },
    )
    wanted = hashlib.sha1(certificate_der).hexdigest()
    matches = []
    for resource in response.get("data", []):
        encoded = resource.get("attributes", {}).get("certificateContent", "")
        try:
            candidate = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            continue
        if hashlib.sha1(candidate).hexdigest() == wanted:
            matches.append(resource)
    if len(matches) != 1:
        raise AutomationError(f"Expected one matching certificate in Apple Developer; found {len(matches)}.")
    if not matches[0].get("attributes", {}).get("activated", True):
        raise AutomationError("The matching Apple signing certificate is inactive.")
    return matches[0]


def current_mac_provisioning_udid() -> str:
    result = subprocess.run(
        ["/usr/sbin/system_profiler", "SPHardwareDataType", "-json"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        return ""
    try:
        return str(json.loads(result.stdout)["SPHardwareDataType"][0]["provisioning_UDID"])
    except (KeyError, IndexError, TypeError, ValueError):
        return ""


def resolve_device(
    client: AppStoreConnectClient,
    udid: str,
    *,
    register: bool,
    device_name: str,
) -> dict[str, Any]:
    response = client.request(
        "GET",
        "/devices",
        query={"filter[platform]": "MAC_OS", "filter[udid]": udid, "limit": "200"},
    )
    resources = response.get("data", [])
    if len(resources) == 1:
        if resources[0].get("attributes", {}).get("status", "ENABLED") != "ENABLED":
            raise AutomationError("The registered build Mac is disabled in Apple Developer.")
        return resources[0]
    if resources:
        raise AutomationError(f"Expected one registered Mac for the local provisioning UDID; found {len(resources)}.")
    if not register:
        raise AutomationError(
            "This Mac is not registered. Register it in Apple Developer or rerun with --register-current-mac."
        )
    payload = {
        "data": {
            "type": "devices",
            "attributes": {"name": device_name, "platform": "MAC_OS", "udid": udid},
        }
    }
    return client.request("POST", "/devices", payload=payload)["data"]


def profile_request_payload(
    *,
    name: str,
    profile_type: str,
    bundle_resource_id: str,
    certificate_resource_id: str,
    device_resource_ids: list[str],
) -> dict[str, Any]:
    relationships: dict[str, Any] = {
        "bundleId": {"data": {"type": "bundleIds", "id": bundle_resource_id}},
        "certificates": {
            "data": [{"type": "certificates", "id": certificate_resource_id}]
        },
    }
    if profile_type == "MAC_APP_DEVELOPMENT":
        if not device_resource_ids:
            raise AutomationError("A registered Mac is required for a development profile.")
        relationships["devices"] = {
            "data": [{"type": "devices", "id": item} for item in device_resource_ids]
        }
    return {
        "data": {
            "type": "profiles",
            "attributes": {"name": name, "profileType": profile_type},
            "relationships": relationships,
        }
    }


def decode_profile(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i", str(path)],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise AutomationError("Apple returned a provisioning profile that security(1) cannot decode.")
    try:
        return plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as exc:
        raise AutomationError("Decoded provisioning profile is not a valid property list.") from exc


def verify_profile_payload(
    profile: dict[str, Any],
    *,
    team_id: str,
    bundle_id: str,
    certificate_der: bytes,
) -> dict[str, str]:
    entitlements = profile.get("Entitlements", {})
    profile_teams = profile.get("TeamIdentifier", [])
    expected_app_id = f"{team_id}.{bundle_id}"
    if team_id not in profile_teams:
        raise AutomationError("Generated profile Team ID does not match MSAA_TEAM_ID.")
    if entitlements.get("com.apple.application-identifier") != expected_app_id:
        raise AutomationError("Generated profile does not authorize the exact sensor App ID.")
    if entitlements.get("com.apple.developer.team-identifier") != team_id:
        raise AutomationError("Generated profile entitlement Team ID does not match.")
    if entitlements.get("com.apple.developer.endpoint-security.client") is not True:
        raise AutomationError(
            "Generated profile is missing com.apple.developer.endpoint-security.client; confirm the approved capability is enabled on this exact App ID and regenerate."
        )
    if certificate_der not in profile.get("DeveloperCertificates", []):
        raise AutomationError("Generated profile does not authorize the selected signing certificate.")
    expiration = profile.get("ExpirationDate")
    if isinstance(expiration, datetime) and expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    if not isinstance(expiration, datetime) or expiration <= datetime.now(timezone.utc):
        raise AutomationError("Generated profile is expired or has no valid expiration date.")
    return {
        "uuid": str(profile.get("UUID", "")),
        "name": str(profile.get("Name", "")),
        "application_identifier": expected_app_id,
        "expiration": expiration.astimezone(timezone.utc).isoformat(),
    }


def write_private_file(path: Path, content: bytes, *, overwrite: bool) -> None:
    path = path.expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise AutomationError(f"Output already exists: {path}; use --overwrite to replace it.") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
    path.chmod(0o600)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=tuple(PROFILE_TYPES), default="development")
    parser.add_argument("--bundle-id", default=os.getenv("MSAA_SENSOR_BUNDLE_ID", DEFAULT_BUNDLE_ID))
    parser.add_argument("--team-id", default=os.getenv("MSAA_TEAM_ID", DEFAULT_TEAM_ID))
    parser.add_argument("--certificate", type=Path, default=Path(os.getenv("MSAA_SIGNING_CERTIFICATE", "~/Downloads/development.cer")).expanduser())
    parser.add_argument("--output", type=Path, default=Path("~/Documents/MSAAEndpointSecuritySensor.provisionprofile").expanduser())
    parser.add_argument("--name", default="")
    parser.add_argument("--key-id", default=os.getenv("ASC_KEY_ID", ""))
    parser.add_argument("--issuer-id", default=os.getenv("ASC_ISSUER_ID", ""))
    parser.add_argument("--api-key", type=Path, default=Path(os.getenv("ASC_PRIVATE_KEY_PATH", "")).expanduser() if os.getenv("ASC_PRIVATE_KEY_PATH") else None)
    parser.add_argument("--register-current-mac", action="store_true")
    parser.add_argument("--device-name", default="MSAA Build Mac")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if not args.key_id or not args.issuer_id or args.api_key is None:
            raise AutomationError(
                "Set ASC_KEY_ID, ASC_ISSUER_ID, and ASC_PRIVATE_KEY_PATH to an authorized App Store Connect API key."
            )
        if not args.api_key.is_file():
            raise AutomationError(f"App Store Connect API private key is missing: {args.api_key}")
        if not args.certificate.is_file():
            raise AutomationError(f"Public signing certificate is missing: {args.certificate}")
        if args.output.exists() and not args.overwrite and not args.dry_run:
            raise AutomationError(f"Output already exists: {args.output}; use --overwrite to replace it.")

        certificate_der = local_certificate_der(args.certificate)
        client = AppStoreConnectClient(args.key_id, args.issuer_id, args.api_key)
        bundle = resolve_bundle(client, args.bundle_id)
        certificate = resolve_certificate(client, certificate_der)
        profile_type = PROFILE_TYPES[args.kind]
        device_ids: list[str] = []
        if profile_type == "MAC_APP_DEVELOPMENT":
            udid = current_mac_provisioning_udid()
            if not udid:
                raise AutomationError("Could not determine this Mac's provisioning UDID.")
            device = resolve_device(
                client,
                udid,
                register=args.register_current_mac,
                device_name=args.device_name,
            )
            device_ids.append(device["id"])

        profile_name = args.name or f"MSAA Endpoint Security {args.kind} {datetime.now(timezone.utc):%Y%m%d%H%M%S}"
        payload = profile_request_payload(
            name=profile_name,
            profile_type=profile_type,
            bundle_resource_id=bundle["id"],
            certificate_resource_id=certificate["id"],
            device_resource_ids=device_ids,
        )
        if args.dry_run:
            print(json.dumps({
                "ready": True,
                "dry_run": True,
                "bundle_id": args.bundle_id,
                "profile_type": profile_type,
                "certificate_type": certificate.get("attributes", {}).get("certificateType", ""),
                "device_registered": bool(device_ids) if profile_type == "MAC_APP_DEVELOPMENT" else None,
                "next_action": "Rerun without --dry-run to create and download the profile.",
            }, indent=2, sort_keys=True))
            return 0

        created = client.request("POST", "/profiles", payload=payload)["data"]
        encoded_profile = created.get("attributes", {}).get("profileContent", "")
        try:
            profile_content = base64.b64decode(encoded_profile, validate=True)
        except (ValueError, TypeError) as exc:
            raise AutomationError("Apple profile response did not contain valid profile content.") from exc
        write_private_file(args.output, profile_content, overwrite=args.overwrite)
        verified = verify_profile_payload(
            decode_profile(args.output),
            team_id=args.team_id,
            bundle_id=args.bundle_id,
            certificate_der=certificate_der,
        )
        print(json.dumps({
            "created": True,
            "profile_id": created.get("id", ""),
            "profile_type": profile_type,
            "output": str(args.output.expanduser().resolve(strict=False)),
            "endpoint_security_entitlement": True,
            **verified,
        }, indent=2, sort_keys=True))
        return 0
    except (AutomationError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

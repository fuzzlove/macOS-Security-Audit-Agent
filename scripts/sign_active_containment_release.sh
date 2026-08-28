#!/bin/sh
set -eu
: "${MSAA_TEAM_ID:?Set non-secret MSAA_TEAM_ID}"
: "${MSAA_DEVELOPER_ID_APPLICATION_IDENTITY:?Set the Keychain identity name, not a key}"
: "${MSAA_PROVISIONING_PROFILE:?Set the approved Endpoint Security Developer ID provisioning profile path}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SENSOR_BUNDLE="$ROOT/dist/active-containment/MSAAEndpointSecuritySensor.app"
SENSOR_CONTENTS="$SENSOR_BUNDLE/Contents"
SENSOR_INFO="$SENSOR_CONTENTS/Info.plist"
PROFILE_PLIST=$(mktemp -t msaa-es-profile.XXXXXX)
SIGN_ENTITLEMENTS=$(mktemp -t msaa-es-entitlements.XXXXXX)
PROFILE_CERT_B64=$(mktemp -t msaa-es-profile-cert-b64.XXXXXX)
PROFILE_CERT=$(mktemp -t msaa-es-profile-cert.XXXXXX)
cleanup() { rm -f "$PROFILE_PLIST" "$SIGN_ENTITLEMENTS" "$PROFILE_CERT_B64" "$PROFILE_CERT"; }
trap cleanup EXIT HUP INT TERM

test -r "$MSAA_PROVISIONING_PROFILE" || { printf 'Endpoint Security profile is not readable: %s\n' "$MSAA_PROVISIONING_PROFILE" >&2; exit 2; }
test -d "$SENSOR_BUNDLE" || { printf 'Missing sensor bundle: %s\n' "$SENSOR_BUNDLE" >&2; exit 2; }
for artifact in "$ROOT/dist/active-containment/MSAAContainmentHelper" "$ROOT/dist/active-containment/MSAAAntiRansomwareEngine/MSAAAntiRansomwareEngine"; do
  test -f "$artifact" || { printf 'Missing artifact: %s\n' "$artifact" >&2; exit 2; }
done

if test -n "${MSAA_SIGNING_KEYCHAIN:-}"; then
  test -r "$MSAA_SIGNING_KEYCHAIN" || { printf 'Configured signing keychain is not readable: %s\n' "$MSAA_SIGNING_KEYCHAIN" >&2; exit 2; }
  IDENTITIES=$(/usr/bin/security find-identity -v -p codesigning "$MSAA_SIGNING_KEYCHAIN" 2>&1 || true)
else
  IDENTITIES=$(/usr/bin/security find-identity -v -p codesigning 2>&1 || true)
fi
IDENTITY_LINE=$(printf '%s\n' "$IDENTITIES" | /usr/bin/grep -F "\"$MSAA_DEVELOPER_ID_APPLICATION_IDENTITY\"" | head -n 1 || true)
IDENTITY_SHA1=$(printf '%s\n' "$IDENTITY_LINE" | sed -n 's/^[[:space:]]*[0-9][0-9]*[.)][[:space:]]*\([0-9A-Fa-f][0-9A-Fa-f]*\) .*/\1/p' | tr '[:lower:]' '[:upper:]')
test -n "$IDENTITY_SHA1" || { printf 'Configured Developer ID Application identity is not available with a private key.\n' >&2; exit 1; }

if /usr/bin/security cms -D -i "$MSAA_PROVISIONING_PROFILE" >"$PROFILE_PLIST" 2>/dev/null; then
  :
elif /usr/bin/openssl smime -inform der -verify -noverify -in "$MSAA_PROVISIONING_PROFILE" -out "$PROFILE_PLIST" >/dev/null 2>&1; then
  :
else
  printf 'Invalid Endpoint Security provisioning profile.\n' >&2
  exit 1
fi
PROFILE_TEAM=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$PROFILE_PLIST" 2>/dev/null || true)
PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)
PROFILE_ES=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$PROFILE_PLIST" 2>/dev/null || true)
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$SENSOR_INFO" 2>/dev/null || true)
test "$PROFILE_TEAM" = "$MSAA_TEAM_ID" || { printf 'Endpoint Security profile Team ID mismatch.\n' >&2; exit 1; }
test "$PROFILE_APP_ID" = "$MSAA_TEAM_ID.$BUNDLE_ID" || { printf 'Endpoint Security profile App ID does not match the sensor bundle.\n' >&2; exit 1; }
test "$PROFILE_ES" = true || { printf 'Profile does not authorize com.apple.developer.endpoint-security.client.\n' >&2; exit 1; }

PROFILE_CERT_MATCH=0
CERT_INDEX=0
while /usr/bin/plutil -extract "DeveloperCertificates.$CERT_INDEX" raw -o "$PROFILE_CERT_B64" "$PROFILE_PLIST" >/dev/null 2>&1; do
  /usr/bin/base64 -D -i "$PROFILE_CERT_B64" -o "$PROFILE_CERT"
  PROFILE_SHA1=$(/usr/bin/openssl x509 -inform DER -in "$PROFILE_CERT" -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')
  if test "$PROFILE_SHA1" = "$IDENTITY_SHA1"; then PROFILE_CERT_MATCH=1; fi
  CERT_INDEX=$((CERT_INDEX + 1))
done
test "$PROFILE_CERT_MATCH" -eq 1 || { printf 'Signing identity certificate is not authorized by the Endpoint Security profile.\n' >&2; exit 1; }

cp "$ROOT/native/anti_ransomware_sensor/AntiRansomwareSensor.entitlements" "$SIGN_ENTITLEMENTS"
/usr/libexec/PlistBuddy -c "Add :com.apple.application-identifier string $PROFILE_APP_ID" "$SIGN_ENTITLEMENTS"
/usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string $PROFILE_TEAM" "$SIGN_ENTITLEMENTS"
cp "$MSAA_PROVISIONING_PROFILE" "$SENSOR_CONTENTS/embedded.provisionprofile"

sign_artifact() {
  if test -n "${MSAA_SIGNING_KEYCHAIN:-}"; then
    /usr/bin/codesign --sign "$MSAA_DEVELOPER_ID_APPLICATION_IDENTITY" --keychain "$MSAA_SIGNING_KEYCHAIN" "$@"
  else
    /usr/bin/codesign --sign "$MSAA_DEVELOPER_ID_APPLICATION_IDENTITY" "$@"
  fi
}
for artifact in "$ROOT/dist/active-containment/MSAAContainmentHelper" "$ROOT/dist/active-containment/MSAAAntiRansomwareEngine/MSAAAntiRansomwareEngine"; do
  sign_artifact --force --options runtime --timestamp "$artifact"
done
sign_artifact --force --options runtime --timestamp --generate-entitlement-der --entitlements "$SIGN_ENTITLEMENTS" "$SENSOR_BUNDLE"
sh "$ROOT/scripts/verify_endpoint_security_signature.sh" "$SENSOR_BUNDLE" "$MSAA_TEAM_ID" "$BUNDLE_ID"

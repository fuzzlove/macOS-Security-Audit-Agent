#!/bin/sh
set -eu

: "${1:?Pass the signed Endpoint Security daemon bundle path}"
BUNDLE=$1
case "$BUNDLE" in
  /*) ;;
  *) BUNDLE="$(CDPATH= cd -- "$(dirname -- "$BUNDLE")" && pwd)/$(basename -- "$BUNDLE")" ;;
esac
EXPECTED_TEAM=${2:-${MSAA_TEAM_ID:-}}
EXPECTED_BUNDLE_ID=${3:-${MSAA_SENSOR_BUNDLE_ID:-com.fuzzlove.MacAuditAgent.EndpointSecuritySensor}}
CONTENTS="$BUNDLE/Contents"
PROFILE="$CONTENTS/embedded.provisionprofile"
INFO="$CONTENTS/Info.plist"
EXECUTABLE="$CONTENTS/MacOS/MSAAEndpointSecuritySensor"

test -d "$BUNDLE" || { printf 'Missing sensor bundle: %s\n' "$BUNDLE" >&2; exit 2; }
test -f "$EXECUTABLE" || { printf 'Missing sensor executable: %s\n' "$EXECUTABLE" >&2; exit 2; }
test -r "$PROFILE" || { printf 'Missing embedded Endpoint Security provisioning profile: %s\n' "$PROFILE" >&2; exit 2; }

TMP_DIR=$(mktemp -d -t msaa-es-signature.XXXXXX)
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM
PROFILE_PLIST="$TMP_DIR/profile.plist"
SIGNED_ENTITLEMENTS="$TMP_DIR/signed-entitlements.plist"
CODE_CERT="$TMP_DIR/code-signing-certificate.der"
PROFILE_CERT_B64="$TMP_DIR/profile-certificate.b64"
PROFILE_CERT="$TMP_DIR/profile-certificate.der"

if /usr/bin/security cms -D -i "$PROFILE" >"$PROFILE_PLIST" 2>/dev/null; then
  :
elif /usr/bin/openssl smime -inform der -verify -noverify -in "$PROFILE" -out "$PROFILE_PLIST" >/dev/null 2>&1; then
  :
else
  printf 'Invalid embedded Endpoint Security provisioning profile.\n' >&2
  exit 1
fi
/usr/bin/codesign --verify --strict --verbose=4 "$BUNDLE"
/usr/bin/codesign -d --entitlements "$SIGNED_ENTITLEMENTS" --xml "$BUNDLE"

PROFILE_TEAM=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$PROFILE_PLIST" 2>/dev/null || true)
PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)
PROFILE_ES=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$PROFILE_PLIST" 2>/dev/null || true)
INFO_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$INFO" 2>/dev/null || true)
SIGNED_APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$SIGNED_ENTITLEMENTS" 2>/dev/null || true)
SIGNED_TEAM=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$SIGNED_ENTITLEMENTS" 2>/dev/null || true)
SIGNED_ES=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.endpoint-security.client' "$SIGNED_ENTITLEMENTS" 2>/dev/null || true)

test -n "$EXPECTED_TEAM" || { printf 'Expected Team ID is required for verification.\n' >&2; exit 1; }
test "$PROFILE_TEAM" = "$EXPECTED_TEAM" || { printf 'Endpoint Security profile Team ID mismatch.\n' >&2; exit 1; }
test "$INFO_BUNDLE_ID" = "$EXPECTED_BUNDLE_ID" || { printf 'Sensor Info.plist bundle identifier mismatch.\n' >&2; exit 1; }
test "$PROFILE_APP_ID" = "$EXPECTED_TEAM.$EXPECTED_BUNDLE_ID" || { printf 'Endpoint Security profile App ID mismatch.\n' >&2; exit 1; }
test "$PROFILE_ES" = true || { printf 'Endpoint Security entitlement is not authorized by the embedded profile.\n' >&2; exit 1; }
test "$SIGNED_APP_ID" = "$PROFILE_APP_ID" || { printf 'Signed application identifier is not authorized by the profile.\n' >&2; exit 1; }
test "$SIGNED_TEAM" = "$PROFILE_TEAM" || { printf 'Signed Team ID is not authorized by the profile.\n' >&2; exit 1; }
test "$SIGNED_ES" = true || { printf 'Endpoint Security entitlement is missing from the sensor signature.\n' >&2; exit 1; }

DETAIL=$(/usr/bin/codesign -d --verbose=4 "$BUNDLE" 2>&1)
CODE_TEAM=$(printf '%s\n' "$DETAIL" | sed -n 's/^TeamIdentifier=//p')
CODE_IDENTIFIER=$(printf '%s\n' "$DETAIL" | sed -n 's/^Identifier=//p')
test "$CODE_TEAM" = "$EXPECTED_TEAM" || { printf 'Code signature Team ID mismatch.\n' >&2; exit 1; }
test "$CODE_IDENTIFIER" = "$EXPECTED_BUNDLE_ID" || { printf 'Code signing identifier mismatch.\n' >&2; exit 1; }

mkdir "$TMP_DIR/code-certificates"
(cd "$TMP_DIR/code-certificates" && /usr/bin/codesign -d --extract-certificates "$BUNDLE")
test -f "$TMP_DIR/code-certificates/codesign0" || { printf 'Code signing leaf certificate is unavailable.\n' >&2; exit 1; }
cp "$TMP_DIR/code-certificates/codesign0" "$CODE_CERT"
CODE_CERT_SHA1=$(/usr/bin/openssl x509 -inform DER -in "$CODE_CERT" -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')
PROFILE_CERT_MATCH=0
CERT_INDEX=0
while /usr/bin/plutil -extract "DeveloperCertificates.$CERT_INDEX" raw -o "$PROFILE_CERT_B64" "$PROFILE_PLIST" >/dev/null 2>&1; do
  /usr/bin/base64 -D -i "$PROFILE_CERT_B64" -o "$PROFILE_CERT"
  PROFILE_CERT_SHA1=$(/usr/bin/openssl x509 -inform DER -in "$PROFILE_CERT" -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')
  if test "$PROFILE_CERT_SHA1" = "$CODE_CERT_SHA1"; then PROFILE_CERT_MATCH=1; fi
  CERT_INDEX=$((CERT_INDEX + 1))
done
test "$PROFILE_CERT_MATCH" -eq 1 || { printf 'Code signing certificate is not authorized by the embedded profile.\n' >&2; exit 1; }

printf 'endpoint_security_signature_valid=true\n'
printf 'team_identifier=%s\n' "$CODE_TEAM"
printf 'signing_identifier=%s\n' "$CODE_IDENTIFIER"

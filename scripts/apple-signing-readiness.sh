#!/bin/bash
set -euo pipefail

CERTIFICATE_PATH="${1:-${MSAA_SIGNING_CERTIFICATE:-}}"
REQUIRE_ENDPOINT_SECURITY=0
PROVISIONING_PROFILE="${MSAA_PROVISIONING_PROFILE:-}"

usage() {
  printf 'usage: %s <certificate.cer> [--require-endpoint-security] [--profile <profile>]\n' "$0" >&2
}

if [[ -z "$CERTIFICATE_PATH" ]]; then
  usage
  exit 2
fi
shift || true
while (($#)); do
  case "$1" in
    --require-endpoint-security) REQUIRE_ENDPOINT_SECURITY=1; shift ;;
    --profile)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      PROVISIONING_PROFILE="$2"
      shift 2
      ;;
    *) usage; exit 2 ;;
  esac
done

[[ -r "$CERTIFICATE_PATH" ]] || { printf 'ERROR CERTIFICATE_NOT_READABLE: %s\n' "$CERTIFICATE_PATH" >&2; exit 1; }

CERT_PEM="$(mktemp -t msaa-signing-cert.XXXXXX)"
PROFILE_PLIST="$(mktemp -t msaa-signing-profile.XXXXXX)"
cleanup() { rm -f "$CERT_PEM" "$PROFILE_PLIST"; }
trap cleanup EXIT

if ! /usr/bin/openssl x509 -in "$CERTIFICATE_PATH" -inform DER -out "$CERT_PEM" 2>/dev/null; then
  /usr/bin/openssl x509 -in "$CERTIFICATE_PATH" -inform PEM -out "$CERT_PEM" 2>/dev/null || {
    printf 'ERROR INVALID_CERTIFICATE\n' >&2
    exit 1
  }
fi

SUBJECT="$(/usr/bin/openssl x509 -in "$CERT_PEM" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
COMMON_NAME="$(printf '%s\n' "$SUBJECT" | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
TEAM_ID="$(printf '%s\n' "$SUBJECT" | sed -n 's/.*OU=\([^,]*\).*/\1/p')"
SHA1="$(/usr/bin/openssl x509 -in "$CERT_PEM" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
EXPIRES="$(/usr/bin/openssl x509 -in "$CERT_PEM" -noout -enddate | cut -d= -f2-)"

printf 'certificate_common_name=%s\n' "$COMMON_NAME"
printf 'team_identifier=%s\n' "$TEAM_ID"
printf 'certificate_sha1=%s\n' "$SHA1"
printf 'certificate_expires=%s\n' "$EXPIRES"

if ! /usr/bin/openssl x509 -in "$CERT_PEM" -checkend 0 -noout >/dev/null; then
  printf 'ERROR CERTIFICATE_EXPIRED\n' >&2
  exit 1
fi

# A leaf certificate marked "Trust as Root" breaks Apple's intended
# leaf -> intermediate -> Apple Root chain and causes codesign to fail with
# errSecInternalComponent. Never repair this by weakening trust evaluation.
TRUST_SETTINGS="$(/usr/bin/security dump-trust-settings 2>/dev/null || true)"
if printf '%s\n' "$TRUST_SETTINGS" | /usr/bin/grep -Fq "Cert 0: $COMMON_NAME" &&
   printf '%s\n' "$TRUST_SETTINGS" | /usr/bin/grep -Fq 'kSecTrustSettingsResultTrustAsRoot'; then
  printf 'ERROR LEAF_CERTIFICATE_TRUSTED_AS_ROOT\n' >&2
  printf 'Restore the leaf certificate to System Defaults trust; do not mark a signing certificate as a root CA.\n' >&2
  exit 1
fi

IDENTITIES="$(/usr/bin/security find-identity -v -p codesigning 2>&1 || true)"
if ! printf '%s\n' "$IDENTITIES" | /usr/bin/grep -Fq "$SHA1"; then
  printf 'ERROR MATCHING_PRIVATE_KEY_NOT_AVAILABLE\n' >&2
  printf 'Import the password-protected .p12 containing the matching private key into the login keychain. A .cer file contains no private key and cannot sign code.\n' >&2
  exit 1
fi
printf 'codesigning_identity_ready=true\n'

case "$COMMON_NAME" in
  'Apple Development:'*)
    printf 'signing_use=local_development\n'
    ;;
  'Developer ID Application:'*)
    printf 'signing_use=developer_id_distribution\n'
    ;;
  *)
    printf 'signing_use=other\n'
    ;;
esac

if ((REQUIRE_ENDPOINT_SECURITY)); then
  [[ -n "$PROVISIONING_PROFILE" && -r "$PROVISIONING_PROFILE" ]] || {
    printf 'ERROR ENDPOINT_SECURITY_PROFILE_REQUIRED\n' >&2
    exit 1
  }
  /usr/bin/security cms -D -i "$PROVISIONING_PROFILE" >"$PROFILE_PLIST" 2>/dev/null || {
    printf 'ERROR INVALID_PROVISIONING_PROFILE\n' >&2
    exit 1
  }
  PROFILE_TEAM="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$PROFILE_PLIST" 2>/dev/null || true)"
  ES_VALUE="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$PROFILE_PLIST" 2>/dev/null || true)"
  [[ "$PROFILE_TEAM" == "$TEAM_ID" ]] || { printf 'ERROR PROFILE_TEAM_MISMATCH\n' >&2; exit 1; }
  [[ "$ES_VALUE" == true ]] || { printf 'ERROR ENDPOINT_SECURITY_ENTITLEMENT_NOT_AUTHORIZED\n' >&2; exit 1; }
  printf 'endpoint_security_profile_ready=true\n'
fi

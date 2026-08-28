#!/usr/bin/env bash
set -euo pipefail

APP_PATH="${1:-}"
if [[ -z "${APP_PATH}" ]]; then
  echo "usage: $0 <path-to-app-bundle>" >&2
  exit 2
fi

if [[ -z "${MSAA_CODESIGN_IDENTITY:-}" ]]; then
  echo "MSAA_CODESIGN_IDENTITY is not set; refusing to sign app bundle." >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [[ -n "${MSAA_SIGNING_CERTIFICATE:-}" ]]; then
  "$SCRIPT_DIR/apple-signing-readiness.sh" "$MSAA_SIGNING_CERTIFICATE"
fi

codesign --force --deep --options runtime --sign "${MSAA_CODESIGN_IDENTITY}" "${APP_PATH}"
codesign --verify --deep --strict --verbose=2 "${APP_PATH}"
codesign --display --verbose=4 "${APP_PATH}"

if [[ -n "${MSAA_NOTARY_PROFILE:-}" ]]; then
  ZIP_PATH="${APP_PATH%/}.zip"
  ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"
  xcrun notarytool submit "${ZIP_PATH}" --keychain-profile "${MSAA_NOTARY_PROFILE}" --wait
  xcrun stapler staple "${APP_PATH}"
  xcrun stapler validate "${APP_PATH}"
fi

echo "macOS app signing workflow completed."

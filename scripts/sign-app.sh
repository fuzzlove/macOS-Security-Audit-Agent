#!/bin/bash
set -euo pipefail
APP=${1:?usage: sign-app.sh <app>}
IDENTITY=${MSAA_DEVELOPER_ID_APPLICATION_IDENTITY:?set MSAA_DEVELOPER_ID_APPLICATION_IDENTITY}
ENTITLEMENTS=${MSAA_APP_ENTITLEMENTS:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/packaging/macos/MSAA.entitlements"}
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [[ -n "${MSAA_SIGNING_CERTIFICATE:-}" ]]; then
  "$SCRIPT_DIR/apple-signing-readiness.sh" "$MSAA_SIGNING_CERTIFICATE"
fi
if [[ "$IDENTITY" != Developer\ ID\ Application:* ]]; then
  echo "A Developer ID Application identity is required for distributable MSAA builds." >&2
  exit 1
fi
find "$APP/Contents" -type f \( -name '*.dylib' -o -name '*.so' \) -print0 | while IFS= read -r -d '' item; do
  /usr/bin/codesign --force --options runtime --timestamp --sign "$IDENTITY" "$item"
done
/usr/bin/codesign --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$APP"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$APP"

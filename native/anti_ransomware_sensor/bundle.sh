#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$ROOT/build/MSAAEndpointSecuritySensor.app"}
BUNDLE_ID=${MSAA_SENSOR_BUNDLE_ID:-com.fuzzlove.MacAuditAgent.EndpointSecuritySensor}
MARKETING_VERSION=${MSAA_SENSOR_VERSION:-1.0}
BUILD_NUMBER=${MSAA_SENSOR_BUILD_NUMBER:-1}

case "$OUT" in
  *.app) ;;
  *) printf '%s\n' "Sensor bundle output must end in .app: $OUT" >&2; exit 2 ;;
esac
case "$BUNDLE_ID" in
  ''|*[!A-Za-z0-9.-]*) printf '%s\n' "Invalid sensor bundle identifier: $BUNDLE_ID" >&2; exit 2 ;;
esac
case "$MARKETING_VERSION" in
  ''|*[!0-9.]*) printf '%s\n' "Invalid sensor marketing version: $MARKETING_VERSION" >&2; exit 2 ;;
esac
case "$BUILD_NUMBER" in
  ''|*[!0-9]*) printf '%s\n' "Invalid sensor build number: $BUILD_NUMBER" >&2; exit 2 ;;
esac

CONTENTS="$OUT/Contents"
EXECUTABLE="$CONTENTS/MacOS/MSAAEndpointSecuritySensor"
mkdir -p "$CONTENTS/MacOS"
rm -rf "$CONTENTS/_CodeSignature"
rm -f "$CONTENTS/embedded.provisionprofile"
cp "$ROOT/Info.plist" "$CONTENTS/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$CONTENTS/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $MARKETING_VERSION" "$CONTENTS/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$CONTENTS/Info.plist"
printf 'APPL????' >"$CONTENTS/PkgInfo"
sh "$ROOT/build.sh" "$EXECUTABLE"
printf '%s\n' "$OUT"

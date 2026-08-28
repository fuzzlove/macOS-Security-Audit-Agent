#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for artifact in "$ROOT/dist/active-containment/MSAAContainmentHelper" "$ROOT/dist/active-containment/MSAAAntiRansomwareEngine/MSAAAntiRansomwareEngine"; do
  codesign --verify --strict --verbose=4 "$artifact"
  codesign -d --verbose=4 "$artifact"
  codesign -d --entitlements :- "$artifact"
  spctl --assess --type execute --verbose=4 "$artifact"
done
SENSOR_BUNDLE="$ROOT/dist/active-containment/MSAAEndpointSecuritySensor.app"
sh "$ROOT/scripts/verify_endpoint_security_signature.sh" "$SENSOR_BUNDLE" "${MSAA_TEAM_ID:?Set non-secret MSAA_TEAM_ID}"
spctl --assess --type execute --verbose=4 "$SENSOR_BUNDLE"

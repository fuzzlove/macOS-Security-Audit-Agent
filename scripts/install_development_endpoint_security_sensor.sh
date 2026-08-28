#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_BUNDLE=${1:-"$ROOT/dist/active-containment/MSAAEndpointSecuritySensor.app"}
TEAM_ID=${MSAA_TEAM_ID:-QPWZZT9ZZK}
BUNDLE_ID=${MSAA_SENSOR_BUNDLE_ID:-com.fuzzlove.MacAuditAgent.EndpointSecuritySensor}
SUPPORT_DIR="/Library/Application Support/MacAuditAgent"
DESTINATION_BUNDLE="$SUPPORT_DIR/bin/MSAAEndpointSecuritySensor.app"
PLIST_SOURCE="$ROOT/packaging/anti_ransomware/com.fuzzlove.MacAuditAgent.EndpointSecuritySensor.plist"
PLIST_DESTINATION="/Library/LaunchDaemons/com.fuzzlove.MacAuditAgent.EndpointSecuritySensor.plist"
LABEL="com.fuzzlove.MacAuditAgent.EndpointSecuritySensor"

test "$(id -u)" -eq 0 || { printf '%s\n' "Administrator approval is required. Rerun with sudo." >&2; exit 77; }
test -d "$SOURCE_BUNDLE" || { printf 'Missing signed sensor bundle: %s\n' "$SOURCE_BUNDLE" >&2; exit 2; }
test -f "$PLIST_SOURCE" || { printf 'Missing LaunchDaemon definition: %s\n' "$PLIST_SOURCE" >&2; exit 2; }

sh "$ROOT/scripts/verify_endpoint_security_signature.sh" "$SOURCE_BUNDLE" "$TEAM_ID" "$BUNDLE_ID"
/usr/bin/plutil -lint "$PLIST_SOURCE"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
/bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
/usr/bin/install -d -o root -g wheel -m 0755 "$SUPPORT_DIR" "$SUPPORT_DIR/bin" "$SUPPORT_DIR/run" "$SUPPORT_DIR/logs"
if test -e "$DESTINATION_BUNDLE"; then
    /bin/mv "$DESTINATION_BUNDLE" "$DESTINATION_BUNDLE.backup-$TIMESTAMP"
fi
if test -e "$PLIST_DESTINATION"; then
    /bin/cp -p "$PLIST_DESTINATION" "$PLIST_DESTINATION.backup-$TIMESTAMP"
fi
/usr/bin/ditto "$SOURCE_BUNDLE" "$DESTINATION_BUNDLE"
/usr/sbin/chown -R root:wheel "$DESTINATION_BUNDLE"
/bin/chmod 0755 "$DESTINATION_BUNDLE" "$DESTINATION_BUNDLE/Contents" "$DESTINATION_BUNDLE/Contents/MacOS" "$DESTINATION_BUNDLE/Contents/_CodeSignature"
/bin/chmod 0644 "$DESTINATION_BUNDLE/Contents/Info.plist" "$DESTINATION_BUNDLE/Contents/PkgInfo" "$DESTINATION_BUNDLE/Contents/embedded.provisionprofile" "$DESTINATION_BUNDLE/Contents/_CodeSignature/CodeResources"
/bin/chmod 0755 "$DESTINATION_BUNDLE/Contents/MacOS/MSAAEndpointSecuritySensor"
/usr/bin/install -o root -g wheel -m 0644 "$PLIST_SOURCE" "$PLIST_DESTINATION"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$DESTINATION_BUNDLE"
sh "$ROOT/scripts/verify_endpoint_security_signature.sh" "$DESTINATION_BUNDLE" "$TEAM_ID" "$BUNDLE_ID"
/bin/launchctl bootstrap system "$PLIST_DESTINATION"
/bin/launchctl kickstart -k "system/$LABEL"
printf 'Installed and started %s\n' "$DESTINATION_BUNDLE"
printf 'Verify with: python3 -m mac_audit_agent.anti_ransomware.cli status --json\n'

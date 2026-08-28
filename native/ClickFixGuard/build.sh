#!/bin/sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPOSITORY_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"
CONFIGURATION="${CONFIGURATION:-release}"
ARCHS="${ARCHS:-arm64 x86_64}"
IDENTITY="${MSAA_CODESIGN_IDENTITY:?Set MSAA_CODESIGN_IDENTITY to the approved Developer ID Application identity}"
TEAM_ID="${MSAA_TEAM_IDENTIFIER:?Set MSAA_TEAM_IDENTIFIER to the approved MSAA Team Identifier}"
CERTIFICATE="${MSAA_SIGNING_CERTIFICATE:-}"
if [ -n "$CERTIFICATE" ]; then
  "$REPOSITORY_ROOT/scripts/apple-signing-readiness.sh" "$CERTIFICATE"
fi
mkdir -p .build/universal/MSAAClickFixGuardAgent.app/Contents/MacOS .build/universal/MSAAClickFixGuardAgent.app/Contents/Resources
for arch in $ARCHS; do
  swift build -c "$CONFIGURATION" --arch "$arch"
done
lipo -create .build/arm64-apple-macosx/$CONFIGURATION/MSAAClickFixGuardAgent .build/x86_64-apple-macosx/$CONFIGURATION/MSAAClickFixGuardAgent -output .build/universal/MSAAClickFixGuardAgent.app/Contents/MacOS/MSAAClickFixGuardAgent
cp Info.plist .build/universal/MSAAClickFixGuardAgent.app/Contents/Info.plist
cp -R .build/arm64-apple-macosx/$CONFIGURATION/MSAAClickFixGuard_ClickFixGuardAgent.bundle .build/universal/MSAAClickFixGuardAgent.app/Contents/Resources/
/usr/bin/codesign --force --options runtime --timestamp --entitlements MSAAClickFixGuardAgent.entitlements --sign "$IDENTITY" .build/universal/MSAAClickFixGuardAgent.app
/usr/bin/codesign --verify --strict --deep --verbose=2 .build/universal/MSAAClickFixGuardAgent.app
echo "Built signed universal ClickFix Guard app for Team $TEAM_ID"

#!/bin/sh
set -eu

cd "$(dirname "$0")"
CONFIGURATION="${CONFIGURATION:-debug}"
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$PWD/.build/module-cache/clang}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-$PWD/.build/module-cache/swiftpm}"
mkdir -p "$CLANG_MODULE_CACHE_PATH" "$SWIFTPM_MODULECACHE_OVERRIDE"
swift build -c "$CONFIGURATION" --product MSAAClickFixGuardAgent
BIN_DIR="$(swift build -c "$CONFIGURATION" --show-bin-path)"
APP=".build/development-demo/MSAAClickFixGuardAgent.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/MSAAClickFixGuardAgent" "$APP/Contents/MacOS/MSAAClickFixGuardAgent"
cp Info.plist "$APP/Contents/Info.plist"
RESOURCE_BUNDLE="$BIN_DIR/MSAAClickFixGuard_ClickFixGuardAgent.bundle"
if [ -d "$RESOURCE_BUNDLE" ]; then
  cp -R "$RESOURCE_BUNDLE" "$APP/Contents/Resources/"
fi
/usr/bin/codesign --force --deep --entitlements MSAAClickFixGuardAgent.entitlements --sign - "$APP"
/usr/bin/codesign --verify --strict --deep --verbose=2 "$APP"
echo "Built ad-hoc signed DEVELOPMENT DEMO at $(pwd)/$APP"
echo "This build is not Developer ID signed, notarized, or suitable for distribution."

#!/bin/sh
set -eu
: "${MSAA_NOTARYTOOL_PROFILE:?Set only the notarytool Keychain profile name}"
: "${1:?Pass the signed archive or package path}"
xcrun notarytool submit "$1" --keychain-profile "$MSAA_NOTARYTOOL_PROFILE" --wait
xcrun stapler staple "$1"
xcrun stapler validate "$1"

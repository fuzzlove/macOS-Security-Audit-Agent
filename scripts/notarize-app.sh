#!/bin/bash
set -euo pipefail
ARCHIVE=${1:?usage: notarize-app.sh <zip-or-dmg>}
PROFILE=${MSAA_NOTARYTOOL_PROFILE:?set MSAA_NOTARYTOOL_PROFILE to an approved keychain profile}
/usr/bin/xcrun notarytool submit "$ARCHIVE" --keychain-profile "$PROFILE" --wait

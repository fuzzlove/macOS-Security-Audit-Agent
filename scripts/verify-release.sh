#!/bin/bash
set -euo pipefail
APP=${1:?usage: verify-release.sh <app> <architecture>}
ARCH=${2:?architecture required}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$ROOT/scripts/verify-architectures.sh" "$APP" "$ARCH"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$APP"
/usr/sbin/spctl --assess --type execute --verbose=4 "$APP"
"$APP/Contents/MacOS/Mac Audit Agent" --doctor --json

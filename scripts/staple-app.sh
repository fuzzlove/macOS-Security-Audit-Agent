#!/bin/bash
set -euo pipefail
APP=${1:?usage: staple-app.sh <app-or-dmg>}
/usr/bin/xcrun stapler staple "$APP"
/usr/bin/xcrun stapler validate "$APP"

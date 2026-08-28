#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
[[ "$(uname -m)" == "x86_64" ]] || { echo "x86_64 release builds require a native Intel runner; Rosetta is test-only" >&2; exit 2; }
[[ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || true)" != "1" ]] || { echo "Rosetta execution is not accepted as a native Intel release build" >&2; exit 2; }
export MSAA_TARGET_ARCH=x86_64
export MSAA_APP_ENTITLEMENTS="$ROOT/packaging/macos/MSAA.entitlements"
PYTHON=${MSAA_BUILD_PYTHON:-python3.12}
"$PYTHON" scripts/build_pyinstaller.py --format onedir --clean --distpath "$ROOT/dist/x86_64"
scripts/verify-architectures.sh "$ROOT/dist/x86_64/Mac Audit Agent.app" x86_64

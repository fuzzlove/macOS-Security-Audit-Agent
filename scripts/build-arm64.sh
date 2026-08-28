#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
[[ "$(uname -m)" == "arm64" ]] || { echo "arm64 release builds require a native Apple Silicon runner" >&2; exit 2; }
[[ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || true)" != "1" ]] || { echo "Rosetta execution cannot produce the native arm64 release artifact" >&2; exit 2; }
export MSAA_TARGET_ARCH=arm64
export MSAA_APP_ENTITLEMENTS="$ROOT/packaging/macos/MSAA.entitlements"
PYTHON=${MSAA_BUILD_PYTHON:-python3.12}
"$PYTHON" scripts/build_pyinstaller.py --format onedir --clean --distpath "$ROOT/dist/arm64"
scripts/verify-architectures.sh "$ROOT/dist/arm64/Mac Audit Agent.app" arm64

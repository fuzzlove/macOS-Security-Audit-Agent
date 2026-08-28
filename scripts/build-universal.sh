#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHON=${MSAA_BUILD_PYTHON:-python3.12}
ARCHS=$(/usr/bin/lipo -archs "$("$PYTHON" -c 'import sys; print(sys.executable)')" 2>/dev/null || true)
[[ "$ARCHS" == *arm64* && "$ARCHS" == *x86_64* ]] || { echo "Universal2 build refused: Python 3.12 is not a verified universal2 interpreter. Use native dual builds." >&2; exit 2; }
export MSAA_TARGET_ARCH=universal2
export MSAA_APP_ENTITLEMENTS="$ROOT/packaging/macos/MSAA.entitlements"
"$PYTHON" scripts/build_pyinstaller.py --format onedir --clean --distpath "$ROOT/dist/universal2"
scripts/verify-architectures.sh "$ROOT/dist/universal2/Mac Audit Agent.app" universal2

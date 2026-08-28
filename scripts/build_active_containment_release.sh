#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/dist/active-containment"
sh "$ROOT/native/containment_helper/build.sh" "$ROOT/dist/active-containment/MSAAContainmentHelper"
sh "$ROOT/native/anti_ransomware_sensor/test.sh"
sh "$ROOT/native/anti_ransomware_sensor/bundle.sh" "$ROOT/dist/active-containment/MSAAEndpointSecuritySensor.app"
PYINSTALLER_TOOLS=${MSAA_PYINSTALLER_TOOLS:-"$ROOT/build/python314-tools"}
if PYTHONPATH="$PYINSTALLER_TOOLS${PYTHONPATH:+:$PYTHONPATH}" python3.14 -m PyInstaller --version >/dev/null 2>&1; then
  PYTHONPATH="$PYINSTALLER_TOOLS${PYTHONPATH:+:$PYTHONPATH}" \
    PYINSTALLER_CONFIG_DIR="$ROOT/build/pyinstaller-config" \
    python3.14 -m PyInstaller --noconfirm --clean \
      --distpath "$ROOT/dist/active-containment" \
      --workpath "$ROOT/build/active-containment-engine" \
      "$ROOT/packaging/anti_ransomware/MSAAAntiRansomwareEngine.spec"
else
  printf '%s\n' 'BLOCKED: Python-3.14-compatible PyInstaller is unavailable. Install it or set MSAA_PYINSTALLER_TOOLS.' >&2
  exit 2
fi

#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$ROOT/build/MSAAEndpointSecuritySensor"}
DEPLOYMENT_TARGET=${MSAA_MACOS_DEPLOYMENT_TARGET:-13.0}
SDK_PATH=$(xcrun --sdk macosx --show-sdk-path)

test -r "$SDK_PATH/usr/include/EndpointSecurity/EndpointSecurity.h" || {
  printf '%s\n' "EndpointSecurity headers are missing from the selected macOS SDK: $SDK_PATH" >&2
  exit 2
}
test -r "$SDK_PATH/usr/lib/libEndpointSecurity.tbd" || {
  printf '%s\n' "libEndpointSecurity is missing from the selected macOS SDK: $SDK_PATH" >&2
  exit 2
}

mkdir -p "$(dirname -- "$OUT")"
xcrun --sdk macosx clang -std=c17 -fblocks -Wall -Wextra -Werror \
  -mmacosx-version-min="$DEPLOYMENT_TARGET" \
  -lEndpointSecurity -framework Foundation \
  "$ROOT/main.c" "$ROOT/sensor_core.c" "$ROOT/sensor_health.c" -o "$OUT"
printf '%s\n' "$OUT"

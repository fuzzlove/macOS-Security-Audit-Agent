#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:-"$ROOT/build/MSAAContainmentHelper"}
mkdir -p "$(dirname -- "$OUT")"
HOST_CHECK=$(mktemp "${TMPDIR:-/tmp}/msaa-containment-self-check.XXXXXX")
trap 'rm -f "$HOST_CHECK"' EXIT INT TERM
xcrun clang -std=c17 -fblocks -mmacosx-version-min=14.4 -Wall -Wextra -Werror \
  "$ROOT/main.c" "$ROOT/message_identity.c" -framework Security -framework CoreFoundation -o "$HOST_CHECK"
"$HOST_CHECK" --self-check
xcrun clang -arch arm64 -std=c17 -fblocks -mmacosx-version-min=14.4 -Wall -Wextra -Werror \
  "$ROOT/main.c" "$ROOT/message_identity.c" -framework Security -framework CoreFoundation -o "$OUT"
printf '%s\n' "$OUT"

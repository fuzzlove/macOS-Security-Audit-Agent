#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${TMPDIR:-/tmp}/msaa-xpc-public-identity-probe
xcrun clang -std=c17 -Wall -Wextra -Werror "$ROOT/main.c" -framework Security -o "$OUT"
"$OUT"

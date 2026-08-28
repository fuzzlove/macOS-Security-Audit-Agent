#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist/external-team/MSAAExternalTeamFixture"}
mkdir -p "$(dirname -- "$OUT")"
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic "$ROOT/native/anti_ransomware_sensor/Tests/containment_fixture_test.c" -o "$OUT"
shasum -a 256 "$OUT"

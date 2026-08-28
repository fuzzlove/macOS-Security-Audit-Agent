#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${TMPDIR:-/tmp}/msaa-ar-sensor-core-test
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic \
  "$ROOT/sensor_core.c" "$ROOT/Tests/test_sensor_core.c" -o "$OUT"
"$OUT"
HEALTH_OUT=${TMPDIR:-/tmp}/msaa-ar-sensor-health-test
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic \
  "$ROOT/sensor_health.c" "$ROOT/Tests/test_sensor_health.c" -o "$HEALTH_OUT"
"$HEALTH_OUT"
CONTAINMENT_OUT=${TMPDIR:-/tmp}/msaa-ar-containment-fixture-test
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic \
  "$ROOT/Tests/containment_fixture_test.c" -o "$CONTAINMENT_OUT"
"$CONTAINMENT_OUT" --self-test
BOUNDARY_OUT=${TMPDIR:-/tmp}/msaa-ar-containment-boundary-test
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic \
  "$ROOT/containment_boundary.c" "$ROOT/Tests/test_containment_boundary.c" -o "$BOUNDARY_OUT"
"$BOUNDARY_OUT"
WATCHDOG_OUT=${TMPDIR:-/tmp}/msaa-ar-containment-watchdog-test
xcrun clang -std=c17 -Wall -Wextra -Werror -pedantic \
  "$ROOT/containment_watchdog.c" "$ROOT/Tests/test_containment_watchdog.c" -o "$WATCHDOG_OUT"
"$WATCHDOG_OUT"

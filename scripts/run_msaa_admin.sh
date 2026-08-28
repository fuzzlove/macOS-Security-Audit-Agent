#!/usr/bin/env bash
set -euo pipefail

APP_PATH="${1:-dist/Mac Audit Agent.app}"
EXECUTABLE="$APP_PATH/Contents/MacOS/Mac Audit Agent"

if [[ ! -x "$EXECUTABLE" ]]; then
  echo "MSAA app executable not found: $EXECUTABLE" >&2
  echo "Usage: scripts/run_msaa_admin.sh [path/to/Mac Audit Agent.app]" >&2
  exit 2
fi

MSAA_GUI_UID="$(id -u)"
MSAA_GUI_GID="$(id -g)"
MSAA_GUI_USER="${USER:-$(id -un)}"
MSAA_GUI_HOME="${HOME}"

exec sudo env \
  "MSAA_GUI_UID=$MSAA_GUI_UID" \
  "MSAA_GUI_GID=$MSAA_GUI_GID" \
  "MSAA_GUI_USER=$MSAA_GUI_USER" \
  "MSAA_GUI_HOME=$MSAA_GUI_HOME" \
  "$EXECUTABLE" "${@:2}"

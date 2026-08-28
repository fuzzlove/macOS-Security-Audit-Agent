#!/bin/sh
set -eu
exec "${PYTHON:-python3}" "$(dirname "$0")/install_clickfix_shell_guard.py" "$@"

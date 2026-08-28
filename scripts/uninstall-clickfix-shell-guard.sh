#!/bin/sh
set -eu
exec "${PYTHON:-python3}" "$(dirname "$0")/uninstall_clickfix_shell_guard.py" "$@"

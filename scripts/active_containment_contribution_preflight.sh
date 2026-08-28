#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3.14 "$ROOT/scripts/active_containment_contribution_preflight.py" "$@"

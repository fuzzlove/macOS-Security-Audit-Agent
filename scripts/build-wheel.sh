#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHON=${MSAA_BUILD_PYTHON:-python3.12}
"$PYTHON" -m build --wheel --no-isolation
"$PYTHON" -m twine check dist/*.whl

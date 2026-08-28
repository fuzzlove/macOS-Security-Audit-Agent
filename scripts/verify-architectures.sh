#!/bin/bash
set -euo pipefail
TARGET=${1:?usage: verify-architectures.sh <artifact> <arm64|x86_64|universal2>}
EXPECTED=${2:?expected architecture required}
[[ -e "$TARGET" ]] || { echo "artifact not found: $TARGET" >&2; exit 2; }
fail=0
while IFS= read -r -d '' file_path; do
  description=$(/usr/bin/file -b "$file_path")
  [[ "$description" == *Mach-O* ]] || continue
  archs=$(/usr/bin/lipo -archs "$file_path" 2>/dev/null || true)
  if [[ "$EXPECTED" == universal2 ]]; then
    [[ "$archs" == *arm64* && "$archs" == *x86_64* ]] || { echo "single-architecture Mach-O in universal2 artifact: $file_path ($archs)" >&2; fail=1; }
  else
    [[ " $archs " == *" $EXPECTED "* ]] || { echo "wrong architecture: $file_path ($archs; expected $EXPECTED)" >&2; fail=1; }
  fi
done < <(find "$TARGET" -type f -print0)
exit "$fail"

#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing to sign release with dirty git tree." >&2
  exit 1
fi

python3 -m compileall -q mac_audit_agent
python3 -m pytest -q
python3 -m mac_audit_agent.quality.pre_uat_audit --full
python3 -m build
python3 -m twine check dist/*
python3 -m mac_audit_agent.quality.clean_install_verify
python3 -m mac_audit_agent.integrity.release_sign all --version "${VERSION}" --mode public_release
python3 -m mac_audit_agent.integrity.release_verify --strict

echo "Release signing complete."
echo "Upload only the signed dist artifacts. Suggested upload:"
echo "python3 -m twine upload dist/*"

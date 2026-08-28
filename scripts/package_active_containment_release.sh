#!/bin/sh
set -eu
: "${MSAA_DEVELOPER_ID_INSTALLER_IDENTITY:?Set the Installer Keychain identity name}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pkgbuild --root "$ROOT/dist/active-containment/package-root" --identifier com.fuzzlove.MacAuditAgent.ActiveContainment --version 1.0 --install-location / "$ROOT/dist/active-containment/unsigned.pkg"
productsign --sign "$MSAA_DEVELOPER_ID_INSTALLER_IDENTITY" "$ROOT/dist/active-containment/unsigned.pkg" "$ROOT/dist/active-containment/MSAAActiveContainment.pkg"
pkgutil --check-signature "$ROOT/dist/active-containment/MSAAActiveContainment.pkg"

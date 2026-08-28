#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Managed installation requires administrator execution.' >&2; exit 1; }
printf '%s\n' 'Use MDM to install reviewed root-owned scanner/adapter artifacts and packaging/clickfix/com.msaa.clickfix.plist. This helper does not alter user startup files without an explicit target-user deployment policy.'

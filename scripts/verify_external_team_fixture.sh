#!/bin/sh
set -eu
: "${1:?Pass signed inert fixture path}"
codesign --verify --strict --verbose=4 "$1"
codesign -d --verbose=4 "$1"
codesign -d --entitlements :- "$1"
file "$1"
shasum -a 256 "$1"

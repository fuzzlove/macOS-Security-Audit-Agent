#!/bin/sh
set -eu
prefix=${MSAA_CLICKFIX_PREFIX:-"${HOME:?}/.local/lib/msaa-clickfix"}
[ -x "$prefix/msaa-clickfix-scan" ] && [ -x "$prefix/msaa-clickfix-adapter" ] && [ -r "$prefix/msaa-clickfix.zsh" ] && [ -r "$prefix/msaa-clickfix.bash" ]
printf '%s\n' 'MSAA ClickFix shell guard files are present. Open a new shell and validate adapter coverage.'

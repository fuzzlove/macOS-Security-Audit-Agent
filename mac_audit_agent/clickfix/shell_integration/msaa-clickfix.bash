# MSAA ClickFix Guard Bash adapter v1.0.0.
[[ $- == *i* ]] || return 0
[[ -n ${MSAA_CLICKFIX_BASH_LOADED:-} ]] && return 0
export MSAA_CLICKFIX_BASH_LOADED=1
: "${MSAA_CLICKFIX_ADAPTER:=__MSAA_ADAPTER_PATH__}"
MSAA_CLICKFIX_SHELL_PATH="$BASH" MSAA_CLICKFIX_SHELL_VERSION="$BASH_VERSION" "$MSAA_CLICKFIX_ADAPTER" --event adapter_loaded </dev/null >/dev/null 2>&1
_msaa_cfx_bash_accept() {
  local line="${READLINE_LINE-}" output decision
  if [[ -z ${READLINE_LINE+x} ]]; then "$MSAA_CLICKFIX_ADAPTER" --event coverage_degraded </dev/null >/dev/null 2>&1; printf '%s\n' 'MSAA ClickFix Guard: coverage degraded; this Bash cannot expose the complete Readline buffer. Use msaa-safe-shell.' >&2; return 0; fi
  output=$(printf '%s' "$line" | MSAA_CLICKFIX_PHASE=accept_line MSAA_CLICKFIX_PASTE_ORIGIN=unknown MSAA_CLICKFIX_SHELL_PATH="$BASH" MSAA_CLICKFIX_SHELL_VERSION="$BASH_VERSION" "$MSAA_CLICKFIX_ADAPTER") || output='{"decision":"error"}'
  decision="${output#*\"decision\":\"}"; decision="${decision%%\"*}"
  if [[ $decision == block || $decision == warn || $decision == error ]]; then READLINE_LINE=''; READLINE_POINT=0; printf '%s\n' 'MSAA held a suspicious command before execution. Re-enter it only after independent review.' >&2; return 0; fi
}
if [[ -n ${BASH_VERSION:-} ]] && bind -x '"\C-x\C-m":_msaa_cfx_bash_accept' 2>/dev/null; then
  bind '"\C-m":"\C-x\C-m\C-m"' 2>/dev/null || printf '%s\n' 'MSAA ClickFix Guard: coverage degraded; Return binding could not be installed.' >&2
else
  "$MSAA_CLICKFIX_ADAPTER" --event coverage_degraded </dev/null >/dev/null 2>&1
  printf '%s\n' 'MSAA ClickFix Guard: coverage degraded; pre-submission Readline inspection unavailable. Use msaa-safe-shell.' >&2
fi

# MSAA ClickFix Guard zsh adapter v1.0.0. Source near the end of .zshrc.
[[ -o interactive ]] || return 0
autoload -Uz add-zsh-hook
zmodload zsh/zle 2>/dev/null || return 0
zmodload zsh/datetime 2>/dev/null || return 0
: ${MSAA_CLICKFIX_ADAPTER:=__MSAA_ADAPTER_PATH__}
typeset -g _MSAA_CFX_PASTED=0 _MSAA_CFX_TRAILING=0 _MSAA_CFX_HELD="" _MSAA_CFX_CHALLENGE="" _MSAA_CFX_EXPIRES=0 _MSAA_CFX_INTEGRITY_FAILED=0
zle -A bracketed-paste msaa-clickfix-original-paste
zle -A accept-line msaa-clickfix-original-accept
MSAA_CLICKFIX_SHELL_PATH="$SHELL" MSAA_CLICKFIX_SHELL_VERSION="$ZSH_VERSION" "$MSAA_CLICKFIX_ADAPTER" --event adapter_loaded </dev/null >/dev/null 2>&1

_msaa_cfx_decision() {
  local phase="$1" output
  REPLY=error
  output=$(print -rn -- "$BUFFER" | MSAA_CLICKFIX_PHASE="$phase" MSAA_CLICKFIX_PASTE_ORIGIN="$([[ $_MSAA_CFX_PASTED == 1 ]] && print paste || print none)" MSAA_CLICKFIX_SHELL_PATH="$SHELL" MSAA_CLICKFIX_SHELL_VERSION="$ZSH_VERSION" "$MSAA_CLICKFIX_ADAPTER" 2>/dev/null) || return 1
  local parsed="${${(S)output#*\"decision\":\"}%%\"*}"
  case "$parsed" in allow|warn|block|error) REPLY="$parsed";; *) REPLY=error;; esac
}
_msaa_cfx_paste() {
  zle msaa-clickfix-original-paste
  _MSAA_CFX_PASTED=1; [[ "$BUFFER" == *$'\n' ]] && _MSAA_CFX_TRAILING=1
  _msaa_cfx_decision paste
  if [[ "$REPLY" == block || "$REPLY" == error ]]; then
    BUFFER=""; CURSOR=0; zle -M 'MSAA blocked a suspicious pasted command before execution. Review downloads, decoding, and interpreter relationships.'
  elif [[ "$REPLY" == warn ]]; then
    [[ "$BUFFER" == *$'\n' ]] && BUFFER="${BUFFER%$'\n'}"
    zle -M 'MSAA warning: this pasted command requires review before execution.'
  fi
}
_msaa_cfx_accept() {
  if [[ -n "$_MSAA_CFX_HELD" ]]; then
    if (( EPOCHSECONDS > _MSAA_CFX_EXPIRES )); then _MSAA_CFX_HELD=""; _MSAA_CFX_CHALLENGE=""; _MSAA_CFX_EXPIRES=0; BUFFER=""; CURSOR=0; "$MSAA_CLICKFIX_ADAPTER" --event user_override_expired </dev/null >/dev/null 2>&1; zle -M 'MSAA challenge expired; the held command was discarded.'
    elif [[ $_MSAA_CFX_PASTED == 0 && "$BUFFER" == "$_MSAA_CFX_CHALLENGE" ]]; then BUFFER="$_MSAA_CFX_HELD"; CURSOR=${#BUFFER}; _MSAA_CFX_HELD=""; _MSAA_CFX_CHALLENGE=""; _MSAA_CFX_EXPIRES=0; "$MSAA_CLICKFIX_ADAPTER" --event user_override_completed </dev/null >/dev/null 2>&1; zle -M 'Challenge accepted. Review the restored command and press Return again to submit.'
    else BUFFER=""; CURSOR=0; zle -M "Challenge required: type $_MSAA_CFX_CHALLENGE manually"; fi
    _MSAA_CFX_PASTED=0; return
  fi
  _msaa_cfx_decision accept_line
  if [[ "$REPLY" == block ]]; then BUFFER=""; CURSOR=0; zle -M 'MSAA blocked a suspicious command before execution.'; _MSAA_CFX_PASTED=0; return; fi
  if [[ "$REPLY" == warn || ( "$REPLY" == error && $_MSAA_CFX_PASTED == 1 ) ]]; then
    _MSAA_CFX_HELD="$BUFFER"; _MSAA_CFX_CHALLENGE="${${$(command uuidgen 2>/dev/null):-${RANDOM}${RANDOM}}//-/}[1,8]"; _MSAA_CFX_EXPIRES=$(( EPOCHSECONDS + 60 )); BUFFER=""; CURSOR=0; _MSAA_CFX_PASTED=0; "$MSAA_CLICKFIX_ADAPTER" --event user_override_started </dev/null >/dev/null 2>&1; zle -M "MSAA held this command. Type $_MSAA_CFX_CHALLENGE manually within 60 seconds, then press Return."; return
  fi
  _MSAA_CFX_PASTED=0; _MSAA_CFX_TRAILING=0; zle msaa-clickfix-original-accept
}
zle -N msaa-clickfix-bracketed-paste _msaa_cfx_paste
zle -N msaa-clickfix-accept-line _msaa_cfx_accept
# Wrap the canonical widget as well as common Return bindings. Without this
# registration, the integrity check would compare the untouched builtin widget
# with MSAA's wrapper and incorrectly report replacement on every prompt.
zle -N accept-line msaa-clickfix-accept-line
bindkey '^M' msaa-clickfix-accept-line
bindkey -M viins '^M' msaa-clickfix-accept-line 2>/dev/null
bindkey -M emacs '^M' msaa-clickfix-accept-line 2>/dev/null
zle -N bracketed-paste msaa-clickfix-bracketed-paste

_msaa_cfx_integrity() {
  if [[ "${widgets[bracketed-paste]}" == user:msaa-clickfix-bracketed-paste && "${widgets[accept-line]}" == user:msaa-clickfix-accept-line ]]; then
    _MSAA_CFX_INTEGRITY_FAILED=0
  elif (( _MSAA_CFX_INTEGRITY_FAILED == 0 )); then
    _MSAA_CFX_INTEGRITY_FAILED=1
    "$MSAA_CLICKFIX_ADAPTER" --event adapter_integrity_failure </dev/null >/dev/null 2>&1
    print -u2 -- 'MSAA ClickFix Guard: adapter integrity failure; protected widgets were replaced. Run Install or Repair Shell Guard after shell plugins finish loading.'
  fi
}
add-zsh-hook precmd _msaa_cfx_integrity

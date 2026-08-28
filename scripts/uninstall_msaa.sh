#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Mac Audit Agent.app"
MONITOR_LABEL="com.mac-audit-agent.monitor"
NOTIFIER_LABEL="com.mac-audit-agent.user-notifier"
CONFIRM_TEXT="UNINSTALL_MSAA"

DRY_RUN=0
REMOVE_DATA=0
REMOVE_SYSTEM=0
APP_PATHS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/uninstall_msaa.sh --dry-run
  scripts/uninstall_msaa.sh --confirm UNINSTALL_MSAA [options]

Options:
  --dry-run                 Print what would be removed.
  --confirm UNINSTALL_MSAA  Required before removing files/services.
  --app PATH                Remove a specific .app bundle. Can be repeated.
  --remove-system           Also unload/remove system LaunchDaemon and system runtime.
  --remove-data             Remove databases, logs, reports, snapshots, and status caches.
  --help                    Show this help.

Default removal scope:
  - Stops/removes user LaunchAgents for MSAA monitor and notifier.
  - Removes user runtime files.
  - Removes app bundles at common install paths and any --app paths.
  - Preserves databases, reports, snapshots, logs, and evidence unless --remove-data is used.

System scope:
  Use --remove-system for /Library LaunchDaemon/runtime cleanup. The script will call sudo
  only for system-owned paths.
USAGE
}

log() {
  printf '%s\n' "$*"
}

run_cmd() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

remove_path() {
  local path="$1"
  local use_sudo="${2:-0}"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi
  if [[ "$use_sudo" == "1" ]]; then
    run_cmd sudo rm -rf "$path"
  else
    run_cmd rm -rf "$path"
  fi
}

bootout_user_plist() {
  local plist="$1"
  if [[ -e "$plist" ]]; then
    run_cmd /bin/launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
  fi
}

bootout_system_plist() {
  local plist="$1"
  if [[ -e "$plist" ]]; then
    run_cmd sudo /bin/launchctl bootout system "$plist" >/dev/null 2>&1 || true
  fi
}

confirmed=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --confirm)
      if [[ "${2:-}" != "$CONFIRM_TEXT" ]]; then
        log "Refusing uninstall: --confirm must be exactly $CONFIRM_TEXT"
        exit 2
      fi
      confirmed=1
      shift 2
      ;;
    --app)
      APP_PATHS+=("${2:?--app requires a path}")
      shift 2
      ;;
    --remove-data)
      REMOVE_DATA=1
      shift
      ;;
    --remove-system)
      REMOVE_SYSTEM=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ "$DRY_RUN" != "1" && "$confirmed" != "1" ]]; then
  log "Refusing uninstall without explicit confirmation."
  log "Run first: scripts/uninstall_msaa.sh --dry-run"
  log "Then run: scripts/uninstall_msaa.sh --confirm $CONFIRM_TEXT"
  exit 2
fi

HOME_DIR="${HOME}"
USER_LAUNCH_AGENTS="${HOME_DIR}/Library/LaunchAgents"
USER_APP_SUPPORT="${HOME_DIR}/Library/Application Support/MacAuditAgent"
USER_LOGS="${HOME_DIR}/Library/Logs/MacAuditAgent"
USER_LEGACY_ROOT="${HOME_DIR}/.mac_audit_agent"
USER_DB="${HOME_DIR}/.mac_audit_agent.sqlite3"
SYSTEM_APP_SUPPORT="/Library/Application Support/MacAuditAgent"
SYSTEM_LOGS="/Library/Logs/MacAuditAgent"
SYSTEM_DAEMON="/Library/LaunchDaemons/${MONITOR_LABEL}.plist"

APP_PATHS+=(
  "/Applications/${APP_NAME}"
  "${HOME_DIR}/Applications/${APP_NAME}"
  "$(pwd)/dist/${APP_NAME}"
)

log "Stopping user services..."
bootout_user_plist "${USER_LAUNCH_AGENTS}/${MONITOR_LABEL}.plist"
bootout_user_plist "${USER_LAUNCH_AGENTS}/${NOTIFIER_LABEL}.plist"

log "Removing user LaunchAgents and runtime..."
remove_path "${USER_LAUNCH_AGENTS}/${MONITOR_LABEL}.plist"
remove_path "${USER_LAUNCH_AGENTS}/${NOTIFIER_LABEL}.plist"
remove_path "${USER_APP_SUPPORT}/runtime"
remove_path "${USER_LEGACY_ROOT}/runtime"

log "Removing app bundle(s)..."
seen_apps=""
for app_path in "${APP_PATHS[@]}"; do
  case ":$seen_apps:" in
    *":$app_path:"*) continue ;;
  esac
  seen_apps="${seen_apps}:$app_path"
  remove_path "$app_path"
done

if [[ "$REMOVE_SYSTEM" == "1" ]]; then
  log "Stopping/removing system LaunchDaemon and system runtime..."
  bootout_system_plist "$SYSTEM_DAEMON"
  remove_path "$SYSTEM_DAEMON" 1
  remove_path "${SYSTEM_APP_SUPPORT}/runtime" 1
fi

if [[ "$REMOVE_DATA" == "1" ]]; then
  log "Removing MSAA data, logs, reports, snapshots, and caches..."
  remove_path "$USER_DB"
  remove_path "$USER_LEGACY_ROOT"
  remove_path "$USER_APP_SUPPORT"
  remove_path "$USER_LOGS"
  if [[ "$REMOVE_SYSTEM" == "1" ]]; then
    remove_path "$SYSTEM_APP_SUPPORT" 1
    remove_path "$SYSTEM_LOGS" 1
  fi
else
  log "Preserved data/evidence by default:"
  log "  $USER_DB"
  log "  $USER_APP_SUPPORT"
  log "  $USER_LOGS"
  log "Use --remove-data to remove preserved databases, logs, reports, snapshots, and evidence."
fi

log "MSAA uninstall completed."

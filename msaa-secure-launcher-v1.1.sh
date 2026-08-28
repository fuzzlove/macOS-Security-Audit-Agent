#!/usr/bin/env bash
#
# MSAA secure setup-and-launch wrapper for macOS.
#
# Run as the logged-in desktop user:
#
#   chmod +x msaa-secure-launcher-v1.1.sh
#   ./msaa-secure-launcher-v1.1.sh --repair
#
# Do NOT run the complete wrapper with sudo. It requests sudo only for
# privileged service operations and keeps the GUI/user notifier in the
# logged-in user's launchd GUI domain.
#

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.1.0"

ACTION="setup"
LAUNCH_MODE="auto"
VERBOSE=1
SKIP_GUI_CHECK=0
NO_GUI=0
PROJECT_ROOT=""

SYSTEM_DAEMON_LABEL="com.mac-audit-agent.monitor"
USER_NOTIFIER_LABEL="com.mac-audit-agent.user-notifier"
ROOT_NOTIFIER_PLIST="/var/root/Library/LaunchAgents/${USER_NOTIFIER_LABEL}.plist"

usage() {
    cat <<'EOF'
Usage:
  ./msaa-secure-launcher-v1.1.sh [options]

Actions:
  --setup         Doctor, GUI safety check, install/reconcile protection,
                  verify services, and launch MSAA. Default.
  --repair        Clean stale root notifier state, repair protection services,
                  verify services, and launch MSAA.
  --launch-only   Skip installation and launch MSAA after user-side checks.
  --verify-only   Run diagnostics and service verification without GUI launch.

Launch options:
  --auto          Prefer dist/MSAA.app; otherwise use launcher.py. Default.
  --app           Require and open dist/MSAA.app.
  --source        Launch launcher.py with Python 3.12.
  --no-gui        Do not launch the GUI.
  --skip-gui-check
                  Skip launcher.py --safe-gui-check. Not recommended.

Other options:
  --project-root PATH
                  Explicit MSAA repository path.
  --quiet         Reduce informational output.
  -h, --help      Show this help.

Recommended recovery from the /var/root notifier defect:
  ./msaa-secure-launcher-v1.1.sh --repair
EOF
}

log() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        printf '[MSAA launcher] %s\n' "$*"
    fi
}

warn() {
    printf '[MSAA launcher] WARNING: %s\n' "$*" >&2
}

die() {
    printf '[MSAA launcher] ERROR: %s\n' "$*" >&2
    exit 1
}

on_error() {
    local exit_code=$?
    local line_no="${1:-unknown}"
    printf '[MSAA launcher] ERROR: command failed at line %s with exit code %s.\n' \
        "$line_no" "$exit_code" >&2
    printf '[MSAA launcher] Review the log at: %s\n' "${LOG_FILE:-<not created>}" >&2
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

while [[ $# -gt 0 ]]; do
    case "$1" in
        --setup)
            ACTION="setup"
            ;;
        --repair)
            ACTION="repair"
            ;;
        --launch-only)
            ACTION="launch-only"
            ;;
        --verify-only)
            ACTION="verify-only"
            NO_GUI=1
            ;;
        --auto)
            LAUNCH_MODE="auto"
            ;;
        --app)
            LAUNCH_MODE="app"
            ;;
        --source)
            LAUNCH_MODE="source"
            ;;
        --no-gui)
            NO_GUI=1
            ;;
        --skip-gui-check)
            SKIP_GUI_CHECK=1
            ;;
        --project-root)
            shift
            [[ $# -gt 0 ]] || die "--project-root requires a path."
            PROJECT_ROOT="$1"
            ;;
        --quiet)
            VERBOSE=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
    shift
done

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    cat >&2 <<'EOF'
Do not run the complete wrapper with sudo.

Run it as the logged-in desktop user:

  ./msaa-secure-launcher-v1.1.sh --repair

The wrapper requests administrator authentication only for protected service
installation and cleanup.
EOF
    exit 2
fi

CURRENT_USER="$(id -un)"
CURRENT_UID="$(id -u)"
CURRENT_GID="$(id -g)"
CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"

[[ "$CURRENT_UID" =~ ^[0-9]+$ ]] || die "Current UID is invalid."
[[ "$CURRENT_GID" =~ ^[0-9]+$ ]] || die "Current GID is invalid."
[[ "$CURRENT_UID" -ne 0 ]] || die "The target GUI user cannot be root."

if [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" && "$CONSOLE_USER" != "$CURRENT_USER" ]]; then
    die "Current user '$CURRENT_USER' is not the active console user '$CONSOLE_USER'."
fi

USER_HOME="$(
    /usr/bin/dscl . -read "/Users/$CURRENT_USER" NFSHomeDirectory 2>/dev/null |
        /usr/bin/awk '{print $2}'
)"
[[ -n "$USER_HOME" && "$USER_HOME" == /* && -d "$USER_HOME" ]] ||
    die "Could not resolve a valid home directory for $CURRENT_USER."

if [[ -z "$PROJECT_ROOT" ]]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    if [[ -f "$SCRIPT_DIR/launcher.py" ]]; then
        PROJECT_ROOT="$SCRIPT_DIR"
    elif [[ -f "$PWD/launcher.py" ]]; then
        PROJECT_ROOT="$PWD"
    else
        die "Could not find launcher.py. Place this script in the MSAA repository or use --project-root."
    fi
fi

PROJECT_ROOT="$(cd -- "$PROJECT_ROOT" && pwd -P)"
LAUNCHER="$PROJECT_ROOT/launcher.py"
APP_BUNDLE="$PROJECT_ROOT/dist/MSAA.app"
USER_NOTIFIER_PLIST="$USER_HOME/Library/LaunchAgents/${USER_NOTIFIER_LABEL}.plist"
USER_RUNTIME_DIR="$USER_HOME/Library/Application Support/MacAuditAgent/runtime"

[[ -f "$LAUNCHER" ]] || die "Missing launcher.py at: $LAUNCHER"

LOG_DIR="$USER_HOME/Library/Logs/Liquidsky Network Security/MSAA"
mkdir -p -- "$LOG_DIR"
chmod 700 -- "$LOG_DIR" 2>/dev/null || true
LOG_FILE="$LOG_DIR/secure-launch-$(date -u '+%Y%m%dT%H%M%SZ').log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log "Wrapper version: $SCRIPT_VERSION"
log "Project root: $PROJECT_ROOT"
log "Desktop user: $CURRENT_USER (uid=$CURRENT_UID gid=$CURRENT_GID)"
log "Console user: ${CONSOLE_USER:-unknown}"
log "User home: $USER_HOME"
log "Action: $ACTION"
log "Launch mode: $LAUNCH_MODE"
log "Log: $LOG_FILE"

select_python() {
    local candidates=(
        "/opt/homebrew/opt/python@3.12/bin/python3.12"
        "/opt/homebrew/bin/python3.12"
        "/usr/local/opt/python@3.12/bin/python3.12"
        "/usr/local/bin/python3.12"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    if command -v python3.12 >/dev/null 2>&1; then
        command -v python3.12
        return 0
    fi

    return 1
}

PYTHON_BIN="$(select_python)" || die "Python 3.12 was not found."
PYTHON_BIN="$(cd -- "$(dirname -- "$PYTHON_BIN")" && pwd -P)/$(basename -- "$PYTHON_BIN")"
PYTHON_DIR="$(dirname -- "$PYTHON_BIN")"

log "Python: $PYTHON_BIN"
"$PYTHON_BIN" --version

run_user_python() {
    (
        cd -- "$PROJECT_ROOT"

        unset PYTHONPATH PYTHONHOME
        unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
        unset LD_PRELOAD BASH_ENV ENV
        unset QT_PLUGIN_PATH QML2_IMPORT_PATH

        export HOME="$USER_HOME"
        export USER="$CURRENT_USER"
        export LOGNAME="$CURRENT_USER"
        export PATH="$PYTHON_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

        "$PYTHON_BIN" "$@"
    )
}

run_privileged_module() {
    # Keep root HOME for the root process, but explicitly preserve a validated
    # target desktop identity. The previous wrapper used env -i without these
    # values, causing Path.home()/fallback logic to target /var/root.
    sudo /usr/bin/env -i \
        HOME="/var/root" \
        USER="root" \
        LOGNAME="root" \
        PATH="$PYTHON_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        SUDO_USER="$CURRENT_USER" \
        SUDO_UID="$CURRENT_UID" \
        SUDO_GID="$CURRENT_GID" \
        MSAA_INVOKING_USER="$CURRENT_USER" \
        MSAA_INVOKING_UID="$CURRENT_UID" \
        MSAA_INVOKING_GID="$CURRENT_GID" \
        MSAA_INVOKING_HOME="$USER_HOME" \
        MSAA_TARGET_USER="$CURRENT_USER" \
        MSAA_TARGET_UID="$CURRENT_UID" \
        MSAA_TARGET_GID="$CURRENT_GID" \
        MSAA_TARGET_HOME="$USER_HOME" \
        "$PYTHON_BIN" "$@"
}

cleanup_stale_root_notifier() {
    local found=0

    if sudo /bin/launchctl print "system/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1; then
        warn "Removing incorrectly registered system-domain user notifier."
        sudo /bin/launchctl bootout "system/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1 || true
        found=1
    fi

    if sudo /bin/launchctl print "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1; then
        log "Stopping the current user notifier before repair."
        sudo /bin/launchctl bootout "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1 || true
        found=1
    fi

    if [[ -e "$ROOT_NOTIFIER_PLIST" ]]; then
        warn "Removing stale root-home LaunchAgent: $ROOT_NOTIFIER_PLIST"
        sudo /bin/rm -f -- "$ROOT_NOTIFIER_PLIST"
        found=1
    fi

    if [[ "$found" -eq 0 ]]; then
        log "No stale root notifier registration was found."
    fi
}

repair_user_notifier_registration() {
    if [[ ! -f "$USER_NOTIFIER_PLIST" ]]; then
        warn "Expected user notifier plist is missing: $USER_NOTIFIER_PLIST"
        return 1
    fi

    log "Validating user notifier plist."
    /usr/bin/plutil -lint "$USER_NOTIFIER_PLIST"

    # Limit ownership repair to the user-scoped notifier and user runtime.
    sudo /usr/sbin/chown "$CURRENT_UID:$CURRENT_GID" "$USER_NOTIFIER_PLIST"
    /bin/chmod 644 "$USER_NOTIFIER_PLIST"

    if [[ -d "$USER_RUNTIME_DIR" ]]; then
        sudo /usr/sbin/chown -R "$CURRENT_UID:$CURRENT_GID" "$USER_RUNTIME_DIR"
    fi

    /bin/launchctl bootout "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1 || true
    /bin/launchctl enable "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" >/dev/null 2>&1 || true

    log "Bootstrapping notifier in gui/${CURRENT_UID}."
    /bin/launchctl bootstrap "gui/${CURRENT_UID}" "$USER_NOTIFIER_PLIST"
    /bin/launchctl kickstart -k "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}"

    local attempt
    for attempt in 1 2 3 4 5; do
        if /bin/launchctl print "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" 2>/dev/null |
            /usr/bin/grep -qE 'state = running|pid = [0-9]+'; then
            log "User notifier is running in gui/${CURRENT_UID}."
            return 0
        fi
        /bin/sleep 1
    done

    warn "User notifier did not remain running."
    /bin/launchctl print "gui/${CURRENT_UID}/${USER_NOTIFIER_LABEL}" 2>&1 || true
    return 1
}

run_install() {
    run_privileged_module \
        -m mac_audit_agent.protection install \
        --mode protected \
        --with-system-daemon \
        --with-user-notifier \
        --apply-current-settings \
        --verify \
        --verbose
}

run_repair() {
    if run_privileged_module \
        -m mac_audit_agent.protection repair \
        --mode protected \
        --with-system-daemon \
        --with-user-notifier \
        --apply-current-settings \
        --verify \
        --verbose; then
        return 0
    fi

    warn "The dedicated repair command failed or is unavailable; falling back to idempotent install."
    run_install
}

log "Running MSAA doctor as the desktop user."
run_user_python -m mac_audit_agent --doctor

if [[ "$SKIP_GUI_CHECK" -eq 0 ]]; then
    log "Running the isolated GUI safety check without sudo."
    if ! run_user_python "$LAUNCHER" --safe-gui-check; then
        die "The GUI safety check failed. Privileged installation was not attempted."
    fi
else
    warn "GUI safety check was skipped."
fi

INSTALL_FAILED=0

case "$ACTION" in
    setup)
        cleanup_stale_root_notifier
        log "Installing or reconciling protected components."
        if ! run_install; then
            INSTALL_FAILED=1
            warn "Initial installation returned a failure. Attempting targeted notifier recovery."
        fi
        ;;
    repair)
        cleanup_stale_root_notifier
        log "Repairing protected components."
        if ! run_repair; then
            INSTALL_FAILED=1
            warn "Protection repair returned a failure. Attempting targeted notifier recovery."
        fi
        ;;
    launch-only|verify-only)
        log "Skipping privileged installation."
        ;;
    *)
        die "Unsupported action: $ACTION"
        ;;
esac

if [[ "$ACTION" == "setup" || "$ACTION" == "repair" ]]; then
    if [[ -f "$USER_NOTIFIER_PLIST" ]]; then
        if ! repair_user_notifier_registration; then
            INSTALL_FAILED=1
        fi
    else
        INSTALL_FAILED=1
        warn "The installer still did not write the notifier into the desktop user's home."
        warn "This indicates an MSAA installer defect, not a Qt failure."
    fi
fi

log "Running privileged protection diagnostics."
if ! run_privileged_module -m mac_audit_agent.protection doctor --verbose; then
    warn "Protection doctor reported a degraded or failed state."
fi

log "Requesting structured protection status."
if ! run_privileged_module -m mac_audit_agent.protection status --json; then
    warn "The status subcommand is unavailable or protection remains degraded."
fi

if [[ "$INSTALL_FAILED" -eq 1 ]]; then
    cat >&2 <<EOF
[MSAA launcher] Protection setup remains incomplete.

Expected notifier:
  $USER_NOTIFIER_PLIST

Incorrect notifier location removed:
  $ROOT_NOTIFIER_PLIST

The GUI may still be launched for diagnostics, but active protection must not
be reported as healthy until the user notifier and daemon heartbeats pass.
EOF
fi

if [[ "$NO_GUI" -eq 1 ]]; then
    log "Verification completed. GUI launch was disabled."
    [[ "$INSTALL_FAILED" -eq 0 ]] || exit 1
    exit 0
fi

launch_source() {
    log "Launching MSAA from source as $CURRENT_USER."
    cd -- "$PROJECT_ROOT"

    unset PYTHONPATH PYTHONHOME
    unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
    unset LD_PRELOAD BASH_ENV ENV
    unset QT_PLUGIN_PATH QML2_IMPORT_PATH

    export HOME="$USER_HOME"
    export USER="$CURRENT_USER"
    export LOGNAME="$CURRENT_USER"
    export PATH="$PYTHON_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    exec "$PYTHON_BIN" "$LAUNCHER"
}

launch_app() {
    [[ -d "$APP_BUNDLE" ]] || die "MSAA.app was not found at: $APP_BUNDLE"
    log "Opening packaged application: $APP_BUNDLE"
    /usr/bin/open "$APP_BUNDLE"
}

case "$LAUNCH_MODE" in
    auto)
        if [[ -d "$APP_BUNDLE" ]]; then
            launch_app
        else
            launch_source
        fi
        ;;
    app)
        launch_app
        ;;
    source)
        launch_source
        ;;
    *)
        die "Unsupported launch mode: $LAUNCH_MODE"
        ;;
esac

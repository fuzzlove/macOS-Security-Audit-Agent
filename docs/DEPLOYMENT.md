# Deployment

## Supported Modes

- source install
- local development run
- PyInstaller macOS app bundle
- user LaunchAgent monitor mode
- optional system LaunchDaemon mode

## Install Steps

1. install Python dependencies
2. run the app in safe mode first
3. review the legal notice
4. choose the monitor mode intentionally
5. verify health checks
6. confirm reports and evidence export paths

## Paths

- local database and reports under `~/Library/Application Support/MacAuditAgent/`
- system runtime under `/Library/Application Support/MacAuditAgent/`
- system plist under `/Library/LaunchDaemons/`

## Uninstall

- stop the monitor
- remove the LaunchAgent or LaunchDaemon
- optionally remove runtime files
- preserve reports, notes, snapshots, and logs unless explicitly instructed otherwise

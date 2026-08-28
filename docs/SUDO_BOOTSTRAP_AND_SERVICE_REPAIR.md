# Secure sudo bootstrap and service repair

`sudo python3.12 launcher.py` is routed before Qt is imported. The root phase validates
`SUDO_UID`, `SUDO_GID`, `SUDO_USER`, the passwd record, home directory, and active console
session. It never starts a root GUI. After service work it writes a short-lived, mode-0600
handoff, permanently sets all user and group IDs, sanitizes the environment, and re-executes
the absolute launcher path as the invoking user.

## Runtime trust boundary

A production LaunchDaemon must execute a signed, root-owned runtime. A user-writable source
checkout is rejected with `BOOTSTRAP_UNSAFE_SOURCE_RUNTIME`. Development staging requires both
`--developer-mode` and `--allow-unsigned-development-runtime`; that exception is recorded and
must not be used for a production deployment. Runtime integrity is never rehashed automatically.

## Established services

* System: `system/com.mac-audit-agent.monitor`
* User: `gui/<uid>/com.mac-audit-agent.user-notifier`

The system runtime is `/Library/Application Support/MacAuditAgent/runtime`. The user notifier
imports from its staged runtime under `~/Library/Application Support/MacAuditAgent/runtime`,
not from a checkout or `PYTHONPATH`.

Status requires live launchd state and heartbeat evidence; plist presence is insufficient.
Endpoint Security and Full Disk Access are checked independently and are not implied by root.

## Commands

```bash
python3.12 launcher.py --doctor
sudo python3.12 launcher.py --doctor
sudo python3.12 launcher.py --repair-protection-services
sudo python3.12 launcher.py --service-status --json
sudo python3.12 launcher.py
```

Use the evidence-preserving removal command when required:

```bash
sudo python3.12 launcher.py --remove-protection-services --target-user <active-console-user>
```

It removes only the exact MSAA launchd registrations. Runtime databases, incident evidence,
quarantine, and logs are preserved.

# MSAA Emergency Protection Mode: Profile and Impact Guide

MSAA Emergency Protection Mode is an incident-response feature. It is not Apple's Lockdown Mode, it does not guarantee containment, and it should not replace an approved incident-response plan. Review this guide before preparing an administrator command.

## What every profile does

Activation runs a read-only preflight, records local system and security inventory, records the authorized operator/reason/ticket, saves rollback evidence, applies only the controls listed below, and keeps an integrity-protected audit trail. Requested monitoring categories only work when the relevant MSAA sensors are installed, authorized, and healthy. Selecting a profile does not grant macOS privacy permissions or Apple entitlements.

## Profile comparison

| Profile | Settings changed | Networking reality | Primary negative effects |
|---|---|---|---|
| Investigation Mode | Enables the macOS Application Firewall if off | No PF isolation; connectivity remains available | Inbound server, sharing, development, discovery, or remote-support applications may prompt or become unreachable |
| Emergency Response | Disables Remote Login (SSH); enables the Application Firewall | Requests restricted networking, but PF isolation is not applied without a separately reviewed allowlist | SSH sessions/administration may be interrupted; inbound applications may prompt or become unreachable |
| Ransomware Response | Disables Remote Login (SSH); enables the Application Firewall | Requests restricted networking, but PF isolation is not applied without a separately reviewed allowlist | Same enforced system impact as Emergency Response; the current profile does not stop encryption, kill processes, quarantine files, or protect backups by itself |
| Critical Zero-Day Response | Disables Remote Login (SSH); enables the Application Firewall | Requests critical isolation, but PF isolation is not applied without a separately reviewed allowlist | Same enforced system impact as Emergency Response; the current profile does not disconnect the Mac or block outbound exploitation traffic |

The three restrictive profiles currently differ in declared incident purpose and requested network posture, not in the system-setting commands actually enforced.

## What activation does not do

- It does not enable Apple's Lockdown Mode.
- It does not disable Wi-Fi, Ethernet, Bluetooth, USB, file sharing, screen sharing, user accounts, or outbound traffic.
- It does not automatically terminate, quarantine, or delete processes or files.
- It does not automatically isolate the host with PF because doing that safely requires an incident-specific, reviewed management/DNS/DHCP allowlist.
- It does not guarantee that malware, ransomware, exploitation, or data loss has stopped.

## Rollback and recovery cautions

MSAA observes the initial Remote Login and Application Firewall states and prepares rollback to those values. Use **Prepare Rollback Command** and review the command before running it. Rollback may require manual recovery if the endpoint loses power, evidence is deleted or damaged, another tool changes the same settings, macOS rejects a command, or remote access was the only management path. Keep local console access available before disabling SSH on a remotely administered Mac.

After activation and after rollback, verify Remote Login, the Application Firewall, required business applications, remote administration, and MSAA audit evidence. Escalate to the incident-response owner if the actual state differs from the report.

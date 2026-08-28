# Persistence-Resistant Artifact Handling

MSAA inventories launchd plists in the user, local-system, and Apple system LaunchAgents and LaunchDaemons locations. It also inventories other persistence families through the existing Persistence Intelligence scanners. A malformed or unreadable non-system launchd plist remains visible as a suspect item instead of being discarded as a parser error.

## Removal workflow

For eligible non-Apple LaunchAgents and LaunchDaemons, MSAA:

1. Validates that the selected path is absolute, is not a symlink, and is inside a bounded remediation directory.
2. Refuses Apple platform labels, `/System/Library` artifacts, and MSAA protection services.
3. Extracts the absolute executable referenced by `Program` or the first `ProgramArguments` value.
4. Reports immutable and append-only flags as removal-resistance evidence.
5. Requires administrator authorization for system-wide artifacts.
6. Preserves a restorable backup before modification.
7. Uses `launchctl bootout` with a fixed argument list; it never constructs a shell command.
8. With separate explicit approval, may use `launchctl kill SIGKILL` for the exact validated domain and label after graceful bootout fails, then retries bootout.
9. Moves the plist into the incident quarantine rather than permanently deleting it.
10. Optionally quarantines the referenced executable as a separate confirmation step.
11. Refuses payload directories, symlinks, relative paths, operating-system paths, and targets whose recorded hash changed.
12. Writes a case manifest containing hashes, paths, flag changes, unload and force-stop status, and rollback locations.

MSAA clears only owner-controlled immutable or append-only flags during an explicitly approved remediation. It does not clear system immutable flags, disable SIP, weaken authenticated root, or alter the sealed system volume. System flags produce `RECOVERY_REQUIRED` guidance.

The normal GUI must not run as root and does not retain an administrator password. A system-wide action must be handed to MSAA's reviewed privileged/headless workflow, where macOS can request administrator authorization. This is preferable to embedding `sudo`, AppleScript password prompts, or shell commands in the GUI.

## Process termination

`launchctl bootout` is the normal identity-bound termination step. An operator can separately authorize the fixed `launchctl kill SIGKILL` fallback for that exact service target. MSAA does not kill processes merely because their name resembles a plist label or executable. If launchd cannot force-stop and boot out the validated job, MSAA preserves the backup and aborts automatic removal. An incident responder can then use the approved emergency-response containment workflow.

## Limits

No application can guarantee that removal “cannot be blocked.” Full Disk Access, administrator rights, MDM policy, SIP, authenticated root, immutable flags, active Endpoint Security policy, filesystem damage, or kernel compromise may block discovery or remediation. MSAA reports these conditions as evidence and coverage limitations rather than bypassing macOS protections.

If a directory cannot be enumerated, MSAA cannot truthfully identify unseen filenames. Run the signed privileged collector or collect from trusted recovery media. When kernel compromise is suspected, preserve evidence before remediation and treat user-space results as potentially incomplete.

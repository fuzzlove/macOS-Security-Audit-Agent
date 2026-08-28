# System Application Control

MSAA's Add/Remove Programs view distinguishes ordinary application removal from system-application containment.

## Safety boundary

An eligible system-installed application is a canonical top-level `.app` bundle in `/Applications` that inventory identifies as system or Apple-platform software. Before an action, MSAA displays both discovered dependencies and an explicit warning that macOS has no complete reverse-dependency graph. The administrator must confirm the warning and type the application name exactly.

MSAA refuses to modify the sealed system volume, SIP/authenticated-root paths, critical macOS components, symlinked or non-canonical bundles, and targets outside the approved top-level application directory. No SIP or TCC bypass is attempted. An Apple signature is evidence of provenance, not proof that software is safe or compromised.

## Disable and removal behavior

Both system actions are containment operations. MSAA revalidates the target and executable digest, gracefully terminates identity-matched non-protected processes, and moves the bundle into `/Library/Application Support/MSAA/Disabled Applications`. “Remove to System Quarantine” is intentionally reversible and is not secure deletion.

The quarantine directory is root-controlled. Each action creates a rollback manifest and a redacted audit record. Existing launch items are reported as dependency impacts but are not silently deleted.

## Administrator authorization

The GUI runs in the logged-in user's session and must not run under `sudo`. The current source build does not contain a signed privileged helper, so it cannot safely display a native macOS password prompt and then perform the root operation. It fails closed after collecting explicit user confirmation unless it is invoked through an already approved privileged MSAA execution boundary.

A production build should connect this exact, hash-bound plan to a signed, minimal `SMAppService`/XPC helper. The helper must authenticate the requesting user, obtain an Authorization Services right, revalidate every path and digest, perform only the fixed containment operation, and return a receipt. Passwords must never be passed to MSAA or stored. AppleScript elevation and shell-interpolated `sudo` are prohibited.

## Dependency warnings

The preview reports declared URL/document handlers, extensions, privileged helpers, embedded login items, XPC services, launch services, frameworks, plugins, inventoried persistence, Apple platform integration, and unknown reverse dependencies. Administrators should validate MDM policy, automations, package receipts, business workflows, recovery access, and an equivalent disposable host before proceeding.

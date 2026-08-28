# Universal Architecture Inventory

## Entry and import boundaries

- `launcher.py` is the source-checkout Stage-0 bootstrap and stays standard-library-only through interpreter selection.
- `mac_audit_agent.bootstrap:main` is the installed/frozen entry boundary. Doctor and integrity paths are lazy and do not require Qt.
- `mac_audit_agent.app` is the GUI boundary. PySide6 is imported only after Python, root-session, and macOS GUI preflight approval.
- `mac_audit_agent.runtime.doctor` is the authoritative structured diagnostic path.

## Platform and native surfaces

- `mac_audit_agent.platform` reports hardware, process, Python, Rosetta, universal2, OS, execution mode, paths, dependencies, and explicit capability states.
- Guarded probes use argument arrays and timeouts for `sysctl`, `lipo`, `codesign`, and related system tools.
- PySide6/Qt, cryptography, lxml, psutil, and packaging bootloaders may contain Mach-O objects and are validated per native artifact.
- Endpoint Security is not claimed merely because macOS supports the API. It remains `NOT_ENTITLED` until a signed, entitled sensor is independently verified.
- Full Disk Access and TCC limitations are reported as permission states, not generic crashes.

## Paths and installed services

- Immutable resources resolve from the source/package or frozen bundle.
- Mutable configuration, databases, caches, logs, and reports resolve outside the signed bundle under macOS Application Support, Caches, and Logs.
- LaunchAgent and LaunchDaemon paths are materialized at explicit installation time; the GUI is never the privileged runtime.

## Packaging and distribution

- The base wheel is pure Python and has optional groups for GUI, exports, network, forensics, development, test, and build workflows.
- PyInstaller is retained for the self-contained application because the repository already has a working Qt-aware specification and resource inventory.
- Release strategy is dual native artifacts: arm64 and x86_64. Universal2 is allowed only when every embedded Mach-O slice validates.
- Signing, notarization, stapling, SBOM, checksums, manifest, and provenance are separate fail-closed release stages.

## Blockers found in the prior architecture

- Architecture detection was scattered and over-relied on process architecture.
- Runtime paths and source-checkout assumptions were mixed with installed execution.
- Architecture-specific build and release verification were not expressed as fail-closed scripts or native CI jobs.
- Build identity and package version could diverge.
- Optional dependencies and unavailable Apple security permissions were not uniformly represented as feature-scoped capability states.

This inventory describes implemented boundaries. Native Intel qualification, Developer ID signing, notarization, Endpoint Security approval, and user-granted privacy permissions remain external release gates.

# MSAA Anti-Ransomware Endpoint Security Sensor Boundary

This directory defines the native boundary; it is not a production-built or entitled sensor artifact.

The preferred deployment is a dedicated signed Endpoint Security system extension/helper communicating with the Python system engine over authenticated local IPC. Callback work is limited to message retention, bounded queue submission, and drain scheduling. Entropy analysis, SQLite, networking, reporting, and UI are prohibited in callbacks.

The callback retains every asynchronously processed message before returning and submits ownership to a fixed 4,096-entry queue. Rejection releases immediately. One serial processing queue drains and releases accepted messages exactly once. Shutdown releases remaining queued ownership. `test.sh` compiles and executes framework-independent sequence, deadline, queue-bound, rejection, drain, and shutdown-release tests.

Production requires Apple's `com.apple.developer.endpoint-security.client` entitlement, appropriate user/MDM approval, hardened signing, Full Disk Access where needed, target-architecture builds, deadline measurement, and live testing. None is implied by this source scaffold.

Run native core tests with `sh test.sh`. Build the development sensor with
`sh build.sh`. The selected macOS SDK must provide the public
`EndpointSecurity` headers and `libEndpointSecurity.tbd`; the API is a system
library, not an Apple framework.

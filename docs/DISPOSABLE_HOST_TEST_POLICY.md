# Disposable Host Test Policy

Privileged installation, fixture signaling, MSAA-component SIGKILL, and reboot each require a current local authorization created by `authorize_disposable_host.py`. Authorization is host-bound, expires within 24 hours, records a test run and operator role, contains no password, and requires explicit disposable/recoverable acknowledgement. Verification is mandatory immediately before each privileged phase. Ordinary developer workstations are not authorized by availability alone.

The fixture root must remain generated, marked, local, non-network, non-removable and free of production data. Emergency cleanup is disclosed and makes the test fail. Authorization never permits signaling an ordinary process.

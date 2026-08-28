# Open-Source Security Lessons for School Districts

This is a design study, not approval to install or execute third-party software. No project was bundled or invoked.

The evaluated families suggest narrow adapters, explicit licensing, bounded subprocesses, signed/hash-verified inputs, staged rule updates, rollback, telemetry-health reporting, tenant isolation, and recommend-only response. Open source is not inherently safe, private, accessible, inexpensive to operate, or suitable for students.

Key decisions are recorded in `OPEN_SOURCE_SECURITY_EVALUATION.json`. Any future integration requires a current license/security/maintenance review and synthetic-data tests. MSAA must never download and execute an untrusted rule or binary, and no adapter may directly perform active response.

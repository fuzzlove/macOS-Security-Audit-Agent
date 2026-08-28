# Static Analysis and Resource Review

The built-in multi-language reviewer scanned the first-party repository after excluding virtual environments and bundled third-party source trees. The corrected scan reviewed 1,444 eligible files. It found no first-party Python shell execution, `eval`, `exec`, unsafe deserialization, or TLS-verification-disable findings. Remaining dynamic SQL findings were reviewed as controlled schema/placeholder construction candidates; bound values were already used in the affected data paths. Test-fixture strings are no longer reported as production credentials.

Security changes made from the review:

- Dynamic SQLite identifiers used by shared storage paths are validated and quoted.
- Event-alert trace updates reject unknown column names.
- Alert integrity-chain table/column pairs are explicitly allowlisted.
- Anti-ransomware migration identifiers and declarations are constrained.
- The reviewer no longer reports virtual-environment or bundled vendor code as first-party MSAA findings.
- Static-review cancellation is cooperative; forced thread termination was removed.

Resource changes made from profiling:

- Navigation pages are built on first access and retained afterward.
- The public default profile is `low_resource`; balanced and thorough profiles remain available.
- Heavy startup refreshes are deferred in low-resource mode.
- ClickFix and monitor panels refresh only while visible and use a 30-second UI interval.
- Static-review tables retain one finding payload per row instead of one copy per cell and display at most 2,000 rows.
- Completed scheduler task history is bounded to prevent lifetime growth.
- Vulnerability-scan worker/controller references are released when a run finishes.

An offscreen startup profile on the review host decreased main-window construction to approximately 2 seconds, with 39 of 40 navigation pages still deferred. Results vary by database size, hardware, macOS version, optional modules, and active evidence volume.

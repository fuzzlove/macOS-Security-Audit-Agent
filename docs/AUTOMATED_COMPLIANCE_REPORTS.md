# Automated Compliance Reports

MSAA compliance reports are evidence-backed technical assessments. They do not constitute certification, authorization, legal advice, or an auditor's final determination.

The engine consumes explicit control definitions and keyed MSAA evidence records. Required evidence that is absent resolves to `NEEDS_REVIEW`; contradictory or failed technical evidence resolves to `FAILED`; only complete passing evidence resolves to `PASSED`. Missing evidence never becomes a pass.

Scores are severity-weighted technical-evidence coverage. The report records the exact earned and maximum weights and explains that `NEEDS_REVIEW` earns no points. Existing framework-specific scoring rules, including CMMC restrictions, remain authoritative and are not replaced by this endpoint-readiness score.

Reports and control rows are stored separately with a report SHA-256, evidence-set reference, generator identity, hostname, timestamp, and audit entry. JSON and HTML exports are always available. PDF export is enabled only when the optional `reportlab` dependency is installed; absence is reported explicitly. Exported files use owner-only permissions and JSON/HTML receive sidecar SHA-256 files.

Scheduling records daily, weekly, or monthly intent and retention policy after administrator authorization. Execution remains the responsibility of the existing signed MSAA scheduler/service boundary; this module does not create an unreviewed background daemon or silently delete historical reports.

AI-generated narrative may be added only through the evidence-bound AI Security Analyst interface. Such output remains identified as analyst assistance, includes confidence, and cannot alter control status or score.

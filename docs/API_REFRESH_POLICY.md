# API Refresh Policy

MSAA uses cache-first refresh for Apple Exposure, CVE/NVD, CISA KEV, EPSS, Apple security references, and framework source validation.

Policy:

- Do not refresh all sources on startup.
- Use fresh cache when available.
- Preserve stale/last-known-good cache on API failure.
- Apply request timeout from active resource budget.
- Apply rate limits and circuit breaker behavior.
- Cap large API pulls and pagination.
- Label stale/offline cache in UI and diagnostics.

Default API timeout is 15 seconds in Balanced mode.

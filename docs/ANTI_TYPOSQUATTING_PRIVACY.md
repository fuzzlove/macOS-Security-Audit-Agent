# Anti-Typosquatting Privacy

Offline generation and local-project audit send no data externally. Live lookup discloses candidate identifiers to the selected official registry only after explicit consent.

Go module paths receive additional protection. `GOPRIVATE` and `GONOPROXY`-style patterns are checked before any public proxy request. Private matches produce redacted local evidence and no network request. The GUI currently treats Go lookups as private by default.

MSAA stores sanitized metadata needed for investigation, not package contents, credentials, maintainer email addresses, arbitrary provider payloads, private source files, or downloaded archives. Reports escape controls and HTML, neutralize CSV formulas, and must redact private paths in executive mode.

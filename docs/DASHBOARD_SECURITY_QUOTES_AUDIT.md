# Dashboard Security Quotes Audit

## Current Widget Location

- File: `mac_audit_agent/ui/main_window.py`
- Data: `STARTUP_STRATEGY_QUOTES` near the top of the file
- Selection helper: `choose_startup_strategy_quote()`
- Formatting helper: `format_startup_strategy_quote()`
- Dashboard label: `_build_dashboard_page()`, `self.startup_quote_label`
- Persistence: selected formatted quote is stored in `background_monitor_state.startup_strategy_quote`

## Current Data Source

The previous implementation used a hardcoded list with several Sun Tzu entries and MSAA-authored “Strategy Note” entries. There was no separate data file, no source metadata, no copyright status, no attribution confidence, no theme tags, and no source-reference field.

## Current Layout

The quote was a standalone `QLabel` added below the dashboard header and above the dashboard logo. It used word wrap and a simple tooltip. There were no controls for next/previous, copy, details, filtering, hiding, or settings.

## Rotation Behavior

The previous behavior selected a random quote on application startup and attempted to avoid repeating the previously stored formatted quote.

## Source Metadata

No structured metadata existed. The source field contained only a short label such as `Sun Tzu` or `Strategy Note`.

## Cropping / Layout Risk

The label wrapped text, but it was not inside a dedicated card with controls. Long text could push dashboard content down without metadata-aware sizing or details dialog support.

## Recommended Refactor Path

1. Move quote data to `mac_audit_agent/assets/security_quotes.json`.
2. Load quotes through `mac_audit_agent/dashboard/security_quotes.py`.
3. Validate quote attribution and copyright metadata with `quote_source_validator.py`.
4. Replace the one-label Sun Tzu section with a `Security Wisdom` card.
5. Preserve the legacy helper functions for tests/backward compatibility, but make them read from the new quote library.
6. Store settings and current quote IDs in background monitor state under `dashboard.security_wisdom.*`.
7. Keep quotes out of forensic/evidence exports and readiness scoring.

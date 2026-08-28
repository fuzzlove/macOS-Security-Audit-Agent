# Apple Exposure Update Guidance Bug

## Failing UI Path

Apple Exposure Assessment card or finding -> `Update Guidance` -> `CveRadarPanel._open_card_update_guidance()` -> `build_apple_exposure_update_guide()`.

## Stack Trace

Observed failure:

```text
mac_audit_agent/ui/cve_radar_panel.py
_open_card_update_guidance()
guide = build_apple_exposure_update_guide(card, inventory, self._radar_payload)

mac_audit_agent/apple_exposure_guidance.py
normalize_apple_exposure_item()
merged.update({key: value for key, value in payload.items() if value not in {None, "", []}})

TypeError: cannot use 'list' as a set element
```

## Root Cause

The normalizer attempted to test arbitrary payload values against a set literal containing a list: `{None, "", []}`. Lists are unhashable and cannot be set elements. Apple Exposure cards legitimately contain list and dictionary fields for CVEs, references, NVD metadata, KEV context, products, and remediation details, so normalization must treat structured values as normal input.

## Affected Function

`mac_audit_agent/apple_exposure_guidance.py::normalize_apple_exposure_item()`

## Affected Payload Examples

```python
{"cves": []}
{"cves": ["CVE-2025-1234"]}
{"nvd": {"cvss": "high"}}
{"references": ["", None, []]}
{"known_exploited": False, "cvss_score": 0}
```

## Final Fix

Added `is_meaningful_value()` to recursively evaluate scalars, lists, tuples, sets, and dictionaries without unhashable set membership. `False` and `0` are retained because they are meaningful security states.

`normalize_apple_exposure_item()` now merges payload fields with:

```python
for key, value in payload.items():
    if is_meaningful_value(value):
        merged[key] = value
```

## UI Fallback

`CveRadarPanel._open_card_update_guidance()` now logs the full traceback and opens a safe error dialog with:

- finding/card title
- CVE list if present
- error type
- safe fallback remediation
- Copy Error Details
- Export Diagnostic Context

## Regression Tests Added

`mac_audit_agent/tests/test_apple_exposure_guidance.py` covers:

- empty list payloads
- non-empty CVE lists
- nested dictionaries
- empty nested values
- preserving `False` and `0`
- multiple CVEs
- no-CVE guidance
- KEV guidance
- UI fallback on guide generation exception
- source regression for `{None, "", []}`

## Pre-UAT

Added `apple_exposure.update_guidance` to the scan audit registry and scan auditor. It builds guidance for representative CVE, no-CVE, list-field, nested-dict, and empty payload cases and fails if guidance is blank or crashes.

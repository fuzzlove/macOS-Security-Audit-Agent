# Apple Exposure Update Guide Audit

## Summary

The Apple Exposure Assessment update guidance path was present but too thin. The selected-card action opened `CveRadarDetailsDialog` with only:

- `card["update_guidance"]`
- `card["recommended_action"]`

When either field was absent or blank, the modal rendered blank or nearly blank content. The no-selection path silently returned and showed no useful fallback.

## Related UI Actions

| Button label | Location | Callback | Selected object expected | Selected object actually passed | Data fields used before fix | Why it could be blank | Fix applied |
|---|---|---|---|---|---|---|---|
| Update Guide | Per-card Apple Exposure card | `CveRadarCardWidget.guidance_requested -> CveRadarPanel._open_card_update_guidance(card)` | Apple Exposure card dict | Card dict from `QListWidgetItem.UserRole` or card widget signal | `update_guidance`, `recommended_action` | Both fields can be missing, empty, renamed, or legacy payloads may use different keys | Replaced with `build_apple_exposure_update_guide(card, inventory, freshness)` and renders full guide text |
| Update Guide | Selected action panel | `CveRadarPanel.open_update_guidance()` | Current selected Apple Exposure card | `self.current_card()` or `None` | Same as above | No selected card returned silently; blank selection gave no instructions | No-selection now builds a meaningful fallback guide |

## Expected Data

The UI receives dict payloads from Apple Exposure forecast cards. Across current and legacy payloads, relevant fields can include:

- `card_id`, `alert_id`, `id`, `finding_id`
- `title`
- `affected_local_product`, `detected_product`, `product`
- `affected_component`, `component`
- `detected_version`, `current_version`, `installed_version`
- `fixed_version`, `recommended_version`
- `forecast_level`, `level`, `severity`
- `applicability`, `applicability_confidence`, `confidence`
- `recommended_action`, `what_to_do`
- `update_guidance`, `update_path`
- `references`, `cves`, `cve_ids`

## Root Cause

The UI treated a short optional string field as the whole guidance body. Blank strings were treated as valid content, and there was no normalization layer for legacy card/finding keys.

## Missing Fallback Behavior

Before the fix, the guide did not handle:

- no selected card
- missing product/component
- missing recommended/fixed version
- stale cached payload
- source update failure
- review-needed applicability
- Safari/WebKit, Xcode/Command Line Tools, KEV, and macOS-specific guidance

## Fix Applied

Added `mac_audit_agent/apple_exposure_guidance.py` with:

- `AppleExposureUpdateGuide`
- `normalize_apple_exposure_item(...)`
- `build_apple_exposure_update_guide(...)`

Updated `mac_audit_agent/ui/cve_radar_panel.py`:

- Button label is now `Update Guidance`.
- Tooltip explains the action.
- No-selection path opens a useful empty-state guide.
- Selected-card path generates structured remediation guidance.
- Diagnostics are logged when the guide opens.

Updated `mac_audit_agent/reporting.py`:

- Apple Exposure report rows include update guidance summary and verification steps.

## Unsupported Claims Avoided

The guidance does not claim compromise, certification, compliance, or guaranteed safety after updating. KEV guidance raises urgency without saying the Mac is hacked.

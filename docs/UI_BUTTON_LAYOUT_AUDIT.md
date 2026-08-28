# UI Button Layout Audit

Date: 2026-07-08

Scope: static source inventory for `mac_audit_agent/ui/*.py`, plus targeted remediation of dense action rows most likely to overflow.

## Inventory Summary

- Buttons discovered in UI source audit: 172
- Unsafe fixed-size button usages in scanned button windows: 0
- Long button labels without nearby tooltip calls: 4
- New runtime audit module: `mac_audit_agent/ui/button_layout_auditor.py`
- New Pre-UAT report path: `docs/PRE_UAT_BUTTON_LAYOUT_AUDIT.md`

## Centralized Button System

- `mac_audit_agent/ui/button_styles.py`
  - Defines canonical variants and size classes.
- `mac_audit_agent/ui/button_text.py`
  - Shortens known long labels and preserves full text as tooltip.
- `mac_audit_agent/ui/button_factory.py`
  - Applies consistent min/max height, tooltip, accessible name, and size policy.
- `mac_audit_agent/ui/responsive_actions.py`
  - Adds wrapping `ResponsiveActionRow` for crowded action groups.
- `mac_audit_agent/ui/button_layout_auditor.py`
  - Checks visible buttons for overlap, clipping, unsafe fixed heights, missing tooltip fallback, and parent-bound violations.

## Remediated High-Risk Areas

| Area | File | Current Issue | Fix |
|---|---|---|---|
| Global navigation | `mac_audit_agent/ui/main_window.py` | Help Menu used fixed height and could appear disproportionate. | Removed fixed height; compact min/max height remains. |
| Operational Health | `mac_audit_agent/ui/operational_health_panel.py` | Many long action buttons in a single horizontal row. | Migrated to `ResponsiveActionRow` and canonical button factory. |
| Network Intelligence | `mac_audit_agent/ui/network_intelligence_panel.py` | Long action row labels could overflow. | Migrated to `ResponsiveActionRow`; shortened common labels with tooltip fallback. |
| Logs | `mac_audit_agent/ui/logs_panel.py` | Combo box and action buttons shared a fixed horizontal row. | Migrated to `ResponsiveActionRow`. |
| Reliability / Incident Mode | `mac_audit_agent/ui/reliability_panel.py` | Incident action buttons could overflow narrow tab widths. | Migrated incident button rows to `ResponsiveActionRow`. |

## Button Design Rules Now Enforced

- Compact buttons: 26-32 px height.
- Normal buttons: 32-38 px height.
- Large buttons: 40-48 px height, reserved for onboarding/wizard CTAs.
- Icon-only buttons must have tooltip and accessible name.
- Long labels are shortened where known and full text moves to tooltip.
- Crowded action rows should use `ResponsiveActionRow`, not a plain `QHBoxLayout`.
- Fixed dimensions should be avoided except documented exceptions.

## Remaining Advisory Items

The static audit still flags a small number of long labels without nearby tooltip calls. These are advisory until runtime geometry proves clipping. Runtime overlap/cropping checks are authoritative when a `QApplication` is available.

Recommended follow-up targets:

- Background Monitor dense action groups.
- Integrity diff dialog action buttons.
- Main Window scan/export action rows.
- Apple Exposure card actions.

## Pre-UAT Integration

Added checks:

- `ui.buttons.inventory`
- `ui.buttons.no_overlap`
- `ui.buttons.no_cropping`
- `ui.buttons.size_policy`
- `ui.buttons.tooltip_accessibility`
- `ui.buttons.navigation_proportional`
- `ui.buttons.action_rows_responsive`
- `ui.buttons.visible_connected`

Static mode writes an inventory report. Runtime mode performs geometry checks and can block on visible overlap or cropping.

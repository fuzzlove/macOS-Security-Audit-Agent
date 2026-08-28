# Dashboard Severity Navigation Audit

## Scope

Audited Dashboard severity summary controls and Findings navigation in `mac_audit_agent/ui/main_window.py`.

## Findings

| File path | Widget name | Visible label | Severity represented | Current click behavior | Target view | Required change |
| --- | --- | --- | --- | --- | --- | --- |
| `mac_audit_agent/ui/main_window.py` | `self.severity_card_widgets[0]`, `self.severity_cards["info"]` | `Info` | Informational / `info` | Static `QFrame`; no mouse, keyboard, or accessible activation. | Results -> Findings | Make card clickable; create findings severity intent; apply `info` filter; focus findings table; show banner. |
| `mac_audit_agent/ui/main_window.py` | `self.severity_card_widgets[1]`, `self.severity_cards["low"]` | `Low` | `low` | Static `QFrame`; no mouse, keyboard, or accessible activation. | Results -> Findings | Make card clickable; create findings severity intent; apply `low` filter; focus findings table; show banner. |
| `mac_audit_agent/ui/main_window.py` | `self.severity_card_widgets[2]`, `self.severity_cards["medium"]` | `Medium` | `medium` | Static `QFrame`; no mouse, keyboard, or accessible activation. | Results -> Findings | Make card clickable; create findings severity intent; apply `medium` filter; focus findings table; show banner. |
| `mac_audit_agent/ui/main_window.py` | `self.severity_card_widgets[3]`, `self.severity_cards["high"]` | `High` | `high` | Static `QFrame`; no mouse, keyboard, or accessible activation. | Results -> Findings | Make card clickable; create findings severity intent; apply `high` filter; focus findings table; show banner. |
| `mac_audit_agent/ui/main_window.py` | `self.severity_card_widgets[4]`, `self.severity_cards["critical"]` | `Critical` | `critical` | Static `QFrame`; no mouse, keyboard, or accessible activation. | Results -> Findings | Make card clickable; create findings severity intent; apply `critical` filter; focus findings table; show banner. |
| `mac_audit_agent/ui/main_window.py` | Dashboard summary labels `self.score_label`, `self.summary_label` | Security score and latest scan summary | Aggregate risk summary | Informational label only. | Results -> Findings | No direct severity action needed; severity cards should handle direct navigation. |
| `mac_audit_agent/ui/main_window.py` | `self.findings_table` | Findings table | All severities | Populated with latest/current payload but lacks programmatic severity filter banner. | Results -> Findings | Add visual filter-level support: active banner, clear filter, show all, back to Dashboard, and focus first match. |

## Severity Model Decision

MSAA currently uses `info`, `low`, `medium`, `high`, and `critical` in the Dashboard and report palette. `Informational` is a user-facing label for `info`. A separate internal `severe` value is not present in the Dashboard cards; navigation maps `severe` to `critical` for compatibility.

## Target Behavior

Dashboard severity cards route to the primary `Results` page, select the `Findings` tab, apply a visual/query-level severity filter, scroll to the first matching row, focus the table, and show a clear filter banner. Zero-count severities still navigate and show an empty filtered state.

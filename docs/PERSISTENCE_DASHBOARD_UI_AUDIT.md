# Persistence Dashboard UI Audit

## Summary

The Persistence Intelligence dashboard previously reused a single summary label under the dashboard tab, leaving the area below the header looking unfinished. Findings and inventory data were available on separate tabs, but the dashboard did not answer the main analyst questions quickly.

## Widgets And Sections

| Widget / Section | Current Data Source | Expected Data Source | Can Be Empty | Empty State | Hide When Empty | Convert To Columns | Polish Implemented |
|---|---|---|---|---|---|---|---|
| Header summary label | `PersistenceScanReport` counts | Scan status, counts, last scan | Yes | “No persistence scan has run yet.” | No | No | Yes |
| Dashboard state label | None before fix | Scan state / failure state | Yes | Run scan / no findings / failed scanner text | No | No | Yes |
| Total Persistence Items card | `report.items` | Item count and last scan time | Yes | “Not scanned” | No | No | Yes |
| High-Risk Findings card | `report.findings` | Critical/high counts | Yes | `0 critical / 0 high` | No | No | Yes |
| New Since Baseline card | `PersistenceItem.baseline_status` | Added/changed counts | Yes | `0 added / 0 changed` | No | No | Yes |
| Suspicious Targets card | item signature/path/target state | Unsigned/temp/missing target counts | Yes | `0 unsigned / 0 temp / 0 missing` | No | No | Yes |
| Scanner Coverage card | `report.coverage` | Healthy/degraded summary | Yes | “Not scanned” | No | No | Yes |
| Top Persistence Risks table | `report.findings` joined to items | Top 10 ranked risk findings | Yes | “No elevated persistence risks detected.” | No | Already table | Yes |
| Mechanism Breakdown table | `report.items` and `report.findings` | Mechanism counts and highest risk | Yes | “No items found” | No | Already table | Yes |
| Dashboard Scanner Coverage table | `report.coverage` | Scanner/status/items/findings/last run/errors | Yes | “No scanner data” | No | Already table | Yes |
| Persistence Inventory table | `report.items` | Mechanism, label, paths, booleans, owner, signature, trust, risk, baseline | Yes | “No persistence data available yet.” | No | Already table | Yes |
| Persistence Findings table | `report.findings` joined to items | Severity, risk, mechanism, label, target, owner, signature, baseline, action | Yes | “No persistence findings detected.” | No | Converted to structured columns | Yes |
| Finding Detail pane | Selected finding row | Full finding and item detail | Yes | “Select a persistence finding to view details.” | No | Detail pane | Yes |
| Chain View | `build_chain_view()` and item lookup | Risk/trust badges plus chain relationships | Yes | Empty until scan | No | HTML sections | Yes |
| Timeline table | `build_timeline()` | Event severity/mechanism/label | Yes | Empty until scan | No | Already table | Yes |
| Baseline compare output | `PersistenceBaselineManager.compare_baseline()` | JSON comparison details | Yes | Created/compared messages | No | Future candidate | Documented |
| Coverage tab | `report.coverage` | Scanner coverage rows | Yes | Empty until scan | No | Already table | Yes |
| Diagnostics tab | `build_diagnostics(report)` | JSON diagnostics | Yes | Empty until scan or failure text | No | Diagnostic text | Existing |
| Report export controls | Current report | HTML/JSON/Markdown export | Yes | Export triggers scan if needed | No | Buttons only | Existing |

## Empty-State Rules Applied

- No scan: “No persistence scan has been run yet. Run Persistence Scan to populate this section.”
- No findings: “No persistence findings detected.”
- No high-risk findings: “No elevated persistence risks detected.”
- No inventory data: “No persistence data available yet.”
- Scanner failure: “Persistence Intelligence failed. View Diagnostics.”

## Remaining Notes

- Baseline comparison is still a JSON detail panel because its structure can contain nested added/removed/modified/hash-change payloads. If it becomes a primary analyst workflow, it should be promoted to a table with the same risk-color helpers.

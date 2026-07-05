# Family & Safety Layout Audit

The Family & Safety Center now uses a responsive two-column Category Guide with a fixed-readable navigation area and a scrollable detail panel. The goal is to avoid clipped category names, cropped long guidance, and narrow action buttons while preserving the existing per-category state isolation.

| Widget Name | Tab/Panel | Layout Type | Minimum Width | Minimum Height | Stretch / Size Policy | Clips Content | Scroll Area | Text Wraps | Buttons Fit | Columns Resize | Recommended Layout Fix |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `FamilySafetyPanel` | Family & Safety root | `QVBoxLayout` | 820 | 620 | Expanding | No | Parent page scroll + child scrolls | Header labels wrap | Yes | N/A | Set root minimum size and expanding policy. |
| Header/subtitle/privacy labels | Root header | Vertical labels | Inherited | Content based | Expanding/minimum | No | Parent page scroll | Yes | N/A | N/A | Keep word wrap enabled for all explanatory text. |
| Profile/action toolbar | Root controls | `QHBoxLayout` | Button-driven | 36 buttons | Buttons minimum-expanding | Low risk | Parent page scroll | Labels concise | Yes | N/A | Buttons have minimum heights, widths, and tooltips. |
| Score card | Summary | `QGridLayout` in card | Inherited | Content based | Expanding | No | Parent page scroll | Yes | N/A | N/A | Keep score labels wrapped and avoid fixed heights. |
| `category_splitter` | Category Guide | `QSplitter(Qt.Horizontal)` | 220 + 520 | Inherited | Detail stretches | No | Detail scroll | Yes | N/A | N/A | Replaced squeezed horizontal layout with splitter. |
| `category_list` | Category navigation | `QListWidget` | 220 | Inherited | Preferred/expanding | No | Native list scroll | Item text visible; tooltip has description | N/A | N/A | Use readable navigation width and category tooltips. |
| `category_detail_scroll` | Category detail | `QScrollArea` | 520 | Inherited | Expanding | No | Yes, widget resizable | Yes | Yes | Yes | Long category content no longer sits in a fixed-height panel. |
| Category title/context/status | Category detail header | Vertical labels | Detail width | Content based | Expanding/minimum | No | Detail scroll | Yes | N/A | N/A | Title only shows title; ID moved to context line. |
| Category description | Category detail | `QTextEdit` | Detail width | 220 | Expanding | No | Native vertical scroll | Widget-width wrap | N/A | N/A | Long NIST/Lockdown guidance remains readable. |
| Category checklist | Category detail | `QTableWidget` | Detail width | 260 | Expanding | No | Native table scroll | Word wrap | N/A | Stretch columns | Checklist and recommendation columns stretch; status sizes to content. |
| Your Changes view | Category detail | `QTextEdit` | Detail width | 160 | Expanding | No | Native vertical scroll | Widget-width wrap | N/A | N/A | Unsaved/saved/completed/remaining items fit without cropping. |
| Reset/action row | Category detail | `QHBoxLayout` | Button-driven | 36 buttons | Minimum-expanding | No | Detail scroll | Button labels visible | Yes | N/A | Buttons have minimum widths and tooltips. |
| Navigation action row | Category detail | `QHBoxLayout` | Button-driven | 36 buttons | Minimum-expanding | No | Detail scroll | Button labels visible | Yes | N/A | Previous/next/overview buttons use explicit minimum widths. |
| Safety Audit table | Safety Audit tab | `QTableWidget` | Inherited | Tab area | Expanding | No | Native table scroll | Word wrap | N/A | Last column stretches | Empty state explains audit is needed. |
| Parent Checklist table | Parent Checklist tab | `QTableWidget` | Inherited | Tab area | Expanding | No | Native table scroll | Word wrap | N/A | Last column stretches | Empty state explains audit is needed. |
| Accessibility table | Accessibility tab | `QTableWidget` | Inherited | Tab area | Expanding | No | Native table scroll | Word wrap | N/A | Last column stretches | Empty state explains audit is needed. |
| Safe Browsing table | Safe Browsing tab | `QTableWidget` | Inherited | Tab area | Expanding | No | Native table scroll | Word wrap | N/A | Last column stretches | Empty state explains audit is needed. |
| Apps table | Apps tab | `QTableWidget` | Inherited | Tab area | Expanding | No | Native table scroll | Word wrap | N/A | Last column stretches | Empty state explains audit is needed. |
| Wizard/Caregiver/Guidance text views | Text tabs | `QTextEdit` | Inherited | 360 | Expanding | No | Native vertical scroll | Widget-width wrap | N/A | N/A | Long guidance wraps and scrolls. |
| Government / NIST Lockdown Profile | Category detail | Scrollable category content | 520 detail | Content based | Expanding | No | Yes | Yes | Yes | Checklist table stretches | Long mappings and explanations remain in scrollable sections. |
| Lockdown Mode Plus | Category detail | Scrollable category content | 520 detail | Content based | Expanding | No | Yes | Yes | Yes | Checklist table stretches | Manual verification and high-risk guidance remain readable. |

## Empty State Rules

- No checklist data: `No checklist items are available for this category yet.`
- No audit/table data: `No data is available yet. Run the Safety Audit to populate this section.`
- No selected category item: `Selected item: No item selected.`
- Pending changes: `Pending changes: none.`

## Follow-Up Guardrails

- Do not add fixed-height category content panels.
- Long category details must stay inside `QScrollArea` or a native scrolling text/table widget.
- New Family & Safety buttons should be created with `make_family_button()` so minimum height, width, and tooltips remain consistent.

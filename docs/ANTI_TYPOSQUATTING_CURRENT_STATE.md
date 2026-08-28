# Anti-Typosquatting Expansion Audit

Baseline recorded on 2026-07-12 before this change: the targeted Anti-Typosquatting, help, navigation, provider, GUI, and export suite reported 54 passed and one failure. The failure made Unicode-confusable domain candidates unreachable when the bounded candidate queue filled first. After the fix and schema-v3 migration test, the same targeted scope reports 56 passed.

Existing working components were preserved: bounded domain/npm/PyPI generation, PyPA normalization, IDNA conversion, reduced versioned confusable screening, four original scores, metadata-only RDAP/npm/PyPI providers, offline CLI, PySide worker page, local watchlist tables, safe JSON/CSV/HTML exports, help registration, and package data inclusion.

Defects or partial areas found:

- package ecosystems were represented by only npm and PyPI branches;
- the generic candidate token could not preserve group/vendor/host components;
- provider sanitization and RDAP coverage were deliberately narrow;
- no local dependency-manifest audit existed;
- no evidence-gated investigation state machine existed;
- version-1 persistence lacked discovered-asset, occurrence, evidence, and investigation tables;
- the page was a single analysis surface rather than the requested multi-view portfolio workspace;
- lookup cache tables existed without full cache orchestration;
- the Unicode/keyboard dataset was an accurately labelled audited subset, not worldwide coverage.

Compatibility decisions:

- Existing JSON schema `1.0` and CLI `analyze` syntax remain readable.
- New ecosystem values are additive.
- Existing version-1 and version-2 databases migrate additively in place to version 3; legacy assets, runs, candidates, cache, and watchlist rows are retained.
- PySide remains outside CLI imports.
- No integrity manifest was regenerated.

Component ownership is split across `models.py`, `normalization.py`, `namespaces.py`, `engine.py`, `scoring.py`, `service.py`, `providers.py`, `project_audit.py`, `investigation.py`, `persistence.py`, `reporting.py`, `cli.py`, and `ui/anti_typosquatting_page.py`. Registry logic is outside PySide widgets and generators perform no network access.

This remains an incremental implementation, not full satisfaction of every acceptance criterion. Similar-name provider search, scheduled watchlist execution, complete portfolio editing, richer evidence persistence, every requested lock-file dialect, executive trend reporting, provider conditional caching/backoff, DNS resolver injection, dynamic NuGet service-index discovery, complete Unicode confusables data, and the complete multi-view GUI workflow remain incomplete. Live provider behavior has not been claimed from mocked tests.

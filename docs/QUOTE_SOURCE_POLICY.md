# Quote Source Policy

MSAA Security Wisdom quotes are UI culture content only. They are not findings, recommendations, compliance evidence, or operational instructions.

## Rules

- Do not fabricate quotes.
- Do not use fake attributions.
- Do not include long copyrighted passages.
- Prefer public-domain historical sources and short proverb entries.
- Modern security quotes may be included only when short, attributed, and legally safe.
- Government/public-sector guidance should usually be paraphrased as `Security Principle`, not presented as a direct quote.
- Paraphrased entries must say `Derived from` in `source_reference`.
- Do not imply endorsement, approval, compliance, certification, or authorization by Apple, CISA, NIST, NSA, DoD, MITRE, PCI SSC, or any other source.
- Disputed-attribution entries must be disabled by default unless clearly labeled.
- Entries with `copyright_status = unknown_do_not_use` must not display.
- Entries with `attribution_confidence = unknown` must not display.
- Translated historical entries must include a translation note when wording may vary.

## Required Metadata

Each quote must include:

- quote ID
- text
- author or `Proverb` / `Security Principle`
- source title
- source type
- region
- culture or country
- era
- at least one theme tag
- security relevance
- attribution confidence
- copyright status
- source reference
- enabled flag

## Known High-Risk Patterns

Avoid generic internet quote lists and commonly misattributed figures unless a primary or scholarly source is available. Do not add fake Einstein, Churchill, NSA, CISA, NIST, or Apple quotes.

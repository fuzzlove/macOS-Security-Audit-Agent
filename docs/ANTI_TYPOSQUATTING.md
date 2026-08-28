# Anti-Typosquatting

## Purpose and authorization

Anti-Typosquatting helps owners and authorized maintainers prioritize realistic mistyped or visually confusing variants of Internet domains, npm packages, and Python distribution names. It does not register domains, publish packages, visit candidate websites, download content, classify similar names as malicious, or provide legal advice.

The multi-ecosystem architecture also models crates.io, RubyGems, NuGet, Maven Central, Go modules, and Composer/Packagist as distinct namespaces. A Maven coordinate is never flattened into an artifact name; publisher scopes, groups, vendors, module hosts, and import projections remain explicit evidence.

## Data flow

Input is parsed and namespace-validated, meaningful name portions are transformed by bounded deterministic generators, results are normalized and deduplicated, four explainable scores are calculated, and the highest-quality candidates are returned. Offline mode performs no network requests. A live lookup requires separate explicit consent because candidate names are disclosed to external RDAP or registry services.

The default result budget is 25. Generation is capped at 500 pre-deduplication and 100 post-deduplication candidates. Two-error generation is disabled and no Cartesian product is constructed.

## Candidate categories

- Human errors: omission, repetition, adjacent transposition, and separator errors.
- Keyboard errors: adjacent-key substitutions from a selected, versioned layout.
- Phonetic fallback: a small audited set of digraph transformations.
- Unicode confusables: a documented local subset used for screening.
- Domain confusion: selected top-level-domain substitution and separately categorized service-word combinations.
- Package confusion: npm scope omission and PyPA/npm separator normalization collisions.

Every candidate retains stable rule identifiers, transformations, locale source, Unicode scripts and code points, and score contributions.

## Scores

- **Human Typo Likelihood** estimates plausibility of accidental input.
- **Impersonation Similarity** evaluates visual, namespace, and trust-word similarity.
- **Defensive Registration Priority** helps order unregistered-looking candidates but never asserts legal or technical availability.
- **Investigation Priority** helps prioritize existing names without asserting malicious intent.

Weights are centralized in `anti_typosquatting/configuration.py` and versioned with the rule set.

## Namespace handling

Domains are accepted only as bare names. URLs, credentials, paths, query strings, fragments, control characters, and bidirectional formatting controls are rejected. Internationalized domains require an available IDNA2008 implementation and are checked again after ASCII conversion for DNS length limits.

Python distribution names follow the PyPA name syntax and normalization rule: lowercase and replace each run of `.`, `_`, and `-` with `-`. npm distinguishes organization scope from package portion and accepts only lowercase registry-style names.

## Unicode limitations

The bundled `MSAA-audited-subset-1` profile is deliberately not advertised as complete UTS #39 conformance. It records Python's Unicode database version and MSAA subset versions. Confusable skeletons are internal comparison evidence and are not registry-normalized identifiers.

Control and bidirectional characters are visibly escaped in UI and machine exports. HTML is escaped and CSV cells that could become spreadsheet formulas are prefixed safely.

## Locale coverage

Verified bundled keyboard subsets currently cover:

- United States English QWERTY
- United Kingdom English QWERTY
- French AZERTY
- German QWERTZ
- Spanish QWERTY
- Italian QWERTY
- Brazilian Portuguese QWERTY
- Polish QWERTY
- Turkish QWERTY

Generic QWERTY is an explicitly labelled fallback. Nordic, Cyrillic, Arabic, Indic, Japanese, Korean, Simplified Chinese, and Traditional Chinese linguistic or transliteration packs are not yet verified and must not be presented as comprehensive coverage. Adding them requires versioned fixtures and reviewed CLDR or other primary-source provenance.

## Lookup terminology

RDAP is used instead of shell WHOIS. DNS is not treated as proof of registration availability. A domain not found through configured RDAP is described as: “No registration data was found. This does not guarantee that the domain is available for purchase.”

A missing package is described as not currently published; registry reservation, dispute, and naming policies may still apply. Providers use HTTPS allowlists, timeouts, response-size limits, redirect validation, structured failures, and metadata-only responses. Packages and candidate websites are never downloaded or opened.

## Defensive workflow

For a high-priority name with no registration data, verify rights and status through an authorized registrar before considering defensive registration. For an existing lookalike, verify internal ownership, preserve metadata, add it to a watchlist, review mail or package exposure through authorized processes, and consult legal counsel before asserting abuse.

For packages, document canonical names, use scopes where supported, pin dependencies, review provenance and attestations, and use the registry's official reporting workflow. Do not publish deceptive or empty placeholders.

## Developer data update

Normal startup never downloads Unicode or locale data. Developers may fetch an official source only with a previously reviewed digest:

```bash
python tools/update_anti_typosquatting_data.py \
  --source confusables \
  --output-dir /tmp/msaa-reviewed-unicode \
  --expected-sha256 REVIEWED_SHA256
```

Review licensing, source version, checksum, generated diff, and fixtures before incorporating data. Never update the integrity manifest as a side effect of data generation.

## Standards basis

- Unicode Technical Standard #39, Unicode Security Mechanisms
- Unicode normalization and CLDR keyboard data
- RFC 5890 and RFC 5891 IDNA2008 architecture
- PyPA Names and Normalization specification
- npm package naming documentation and policy
- ICANN Registration Data Access Protocol guidance
- NIST SP 800-204D and NIST SP 800-218 supply-chain practices

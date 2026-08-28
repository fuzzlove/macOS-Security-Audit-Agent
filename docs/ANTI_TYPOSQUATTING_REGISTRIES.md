# Anti-Typosquatting Registry Matrix

Validated 2026-07-12 against primary registry documentation. All requests are metadata-only, HTTPS, allowlisted, bounded, and consent-driven.

| Namespace | Identity | Comparison | Provider | Limitations |
|---|---|---|---|---|
| Domain | labels and registrable name | IDNA ASCII | authoritative RDAP subset | `.com`, `.net`, `.org` configured; no availability claim |
| npm | optional scope plus package | lowercase | registry.npmjs.org | no archive or lifecycle retrieval |
| PyPI | distribution name | PyPA normalized | pypi.org JSON | no wheel/sdist retrieval |
| crates.io | Cargo package | lowercase; import projection retained | crates.io API | owners/yanks depend on response completeness |
| RubyGems | gem name | lowercase; require projection retained | RubyGems API | gem and require name are not equivalent |
| NuGet | Package ID and prefix | case-insensitive | NuGet V3 registration | custom feeds require future dynamic service-index adapter |
| Maven Central | groupId:artifactId | component-preserving | Central Search API | matching artifact under another group is not fraud |
| Go module | full module path | case-sensitive proxy escape | GOPROXY `@latest` | public lookup prohibited for private paths |
| Packagist | vendor/package | lowercase components | Composer v2 metadata | replacement/abandoned fields depend on metadata |

Provider responses are sanitized. Homepages and repository URLs are display evidence only and are never followed automatically.

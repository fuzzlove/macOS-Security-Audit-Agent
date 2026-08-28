# Provider Maintenance

Last primary-document review: 2026-07-12.

Primary references reviewed: npm registry documentation (`https://docs.npmjs.com/using-npm/registry.html`), PyPI JSON API (`https://docs.pypi.org/api/json/`), Cargo registry index (`https://doc.rust-lang.org/cargo/reference/registry-index.html`), RubyGems API (`https://guides.rubygems.org/rubygems-org-api/`), NuGet V3 service index (`https://learn.microsoft.com/en-us/nuget/api/service-index`), Maven Central search API (`https://central.sonatype.org/search/rest-api-guide/`), Go Modules Reference (`https://go.dev/ref/mod`), Composer repositories (`https://getcomposer.org/doc/05-repositories.md`), and IANA RDAP bootstrap data (`https://data.iana.org/rdap/`).

Before changing a provider, verify the official protocol, endpoint discovery rules, acceptable-use/rate-limit requirements, response schema, redirect behavior, maximum expected response, conditional request support, and metadata retention policy. Update provider mocks before enabling live integration tests.

Never replace an official API with HTML scraping. Never enable package-content, homepage, repository, publish, install, or abuse-submission endpoints. NuGet custom sources must discover resources from the V3 service index. Go public proxy requests must pass private-pattern checks. Packagist requests should prefer Composer v2 package metadata. RubyGems requests must follow published rate limits. crates.io clients must use an identifiable user agent and current official access policy.

Integration tests remain opt-in and must use synthetic or project-controlled identifiers. Provider failure must never become an “all clear” result.

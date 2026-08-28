# Local Project Dependency Audit

The scanner walks one explicitly authorized root without following symlinks, skips dependency/build directories, processes at most 2,000 recognized files, and rejects files larger than 5 MB. It never invokes npm, pip, cargo, gem, NuGet, Maven, Gradle, Go, Composer, Git, or project scripts.

Implemented parsers cover `package.json`, npm lock JSON, `pyproject.toml`, requirement and common Python lock text, Cargo TOML, Gemfile/Gemfile.lock/gemspec, NuGet project XML and lock JSON, Maven POM, basic Gradle coordinates, `go.mod`/`go.work`, Composer JSON/lock, and JSON CycloneDX/SPDX package URLs.

Malformed files become structured scanner errors. Near matches are correlated locally against deterministic candidates. Production occurrences receive higher supply-chain reachability than development occurrences. Registry overrides and direct Git/HTTP declarations are retained as source evidence but never contacted.

Limitations: complex Gradle execution, YAML lock formats, generated MSBuild properties, advanced Poetry/uv lock structures, and SPDX tag/value files require future dedicated parsers. No parser evaluates executable build language.

# RCE CVE data

The privileged monitor performs no feed retrieval. The least-privileged administrative import accepts a bounded normalized JSON file from an approved process. Each record retains provider name, source identifier, timestamps, format/parser versions, content hash, validation status, and expiration. Runtime detection continues when the cache is absent or stale.

Version checks use Python Packaging version semantics and reject unparsable versions. Exact exposure requires exact normalized product identity, an affected range match, no known vendor backport, and no known mitigation. Backport metadata overrides a numerical range match. Exposure is never proof of exploitation. Behavior-only correlation is `BEHAVIORALLY_SIMILAR_TO_CVE` until product, version, path, and prerequisites are verified.

The normalized import format is schema `1.0` with `source_name`, `retrieved_at`, and `records`. Each record requires `cve_id`, `product`, concise `summary`, and `affected` ranges using `introduced`, `fixed`, or `last_affected`. Administrators must transform NVD/vendor/CISA data through a reviewed offline pipeline; this release does not authenticate or download those feeds.

# ClickFix Adversarial Validation Corpus

This corpus supplies suspicious-looking strings only as JSON or direct Python scanner input. It never invokes a shell, AppleScript, a downloader, DNS, sockets, persistence utilities, credential tools, or decoded content. Every URL uses `example.invalid`; destructive and credential-collection cases use scanner-test-only symbolic tokens.

Run `python -m pytest -q tests/clickfix` and then `python scripts/run_clickfix_corpus.py`. The runner writes `reports/clickfix-corpus-results.json` and refreshes the measured coverage matrix. A passing simulated endpoint-context fixture proves only the mapping logic; it does not prove Endpoint Security entitlement, collection, or prevention.

Fixture metadata records identity, category, inert text, paste context, shell, expected decision, minimum score, required rules, prohibited side effects, campaign relevance, and limitations. Chain tests retain command hashes, path tokens, timestamps, categories, and session identity—not raw commands.

Safety tests reject execution APIs, `shell=True`, network/DNS APIs, unsafe domains, raw-command logging, and destructive fixtures that are not symbolic. PTY tests statically validate the pre-forward hold and trailing-newline removal; interactive terminal qualification remains manual because automated execution of adversarial strings is prohibited.

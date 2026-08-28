# ClickFix False-Positive Analysis

The benign controls cover standalone download, decoding without execution, local Python printing, benign AppleScript notification text, ordinary permissions, attribute listing, service listing, Keychain lookup without secret output, Git, Homebrew, multiline functions, and long here-documents. A hard block on any benign fixture is a false positive and fails the corpus.

Scores are relationship-driven. Utility names alone do not establish maliciousness. Audit deployments should review score distributions and rule IDs before moving to Warn or Block. Exceptions must use exact hashes through managed policy; broad downloader-to-shell allowlists are unsafe. Current measured failures and missing rules are recorded in `reports/clickfix-corpus-results.json`, rather than removed from expectations.

# Application Installation

Download the artifact matching the Mac's native architecture, verify its published SHA-256 and release manifest, then open the signed/notarized app. The packaged app embeds Python and does not require pip, Homebrew, or Command Line Tools.

Mutable databases, logs, caches, and reports remain outside the signed bundle. Active Protection is a separate explicit administrator workflow. Uninstall with `scripts/uninstall_msaa.sh` after reviewing the components it removes; preserve evidence and reports as required by local policy.

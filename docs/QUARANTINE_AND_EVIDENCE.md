# Quarantine and Evidence

Production quarantine must be root-owned mode 0700. Items are regular, non-symlink, single-link, size-bounded files moved atomically where possible or copied and hash-verified across volumes. Original path, owner, mode, size, SHA-256, reason, incident, and timestamp are retained. Files are never automatically deleted.

Restore requires explicit authorization, an intact hash, and a non-existing destination. Development manifests are labelled `unsigned_hash_manifest`; a hash chain is tamper-evident, not immutable. Evidence defaults to metadata and excludes document contents and credentials.

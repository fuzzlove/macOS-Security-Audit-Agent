# Anti-Ransomware Incident Vault

Schema version 3 stores complete incident summary state, normalized process/file/signal/decision/action entities, complete containment leases, sanitized notification deliveries, sequence gaps, evidence artifacts, and append-only hash-chain custody entries.

Opening an existing vault runs `quick_check`, refuses a newer schema, and creates a SQLite backup before migration. Corrupt input is never overwritten: it is copied to a `.corrupt` recovery artifact and opening fails. Version-3 column migration runs inside a transaction. New database files are mode `0600`; newly created vault directories are mode `0700`. Installed ownership and root/user separation remain packaging responsibilities and require live validation.

Migration creates a protected sidecar marker naming the verified backup. If startup finds an interrupted migration, it validates the backup with read-only `quick_check`, atomically restores it, and retries migration. Missing or corrupt recovery evidence causes an explicit recovery error instead of destructive initialization.

Incident updates use `ON CONFLICT DO UPDATE`, not SQLite replacement semantics, so dependent evidence and containment rows remain intact. WAL uses a 5-second busy timeout and 8 MiB journal limit; an explicit truncating checkpoint is available. Tests cover four concurrent writers and 100 incident transactions without loss.

Failure injection covers a full SQLite page budget with transactional rollback, exclusive database locking with bounded failure and subsequent recovery, read-only write rejection, corrupt input, missing migration backup, and interrupted migration restoration.

Exports contain deterministic JSON and a SHA-256 sidecar. Retention requires explicit authorization and never erases custody history. The user notifier uses its sanitized per-user queue and does not open this vault.

Local hash chaining detects accidental or unauthorized history changes when the attacker has not recomputed the chain. It is not described as tamper-proof against a root-capable attacker.

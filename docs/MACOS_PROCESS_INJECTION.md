# macOS process-injection assurance

MSAA classifies process injection only from structured loader, Mach task-port, memory-write, thread-state, exception-port, ptrace, or memory-image evidence. An unsigned process, shell child, crash, or writable/executable region alone is not proof of injection.

Named classifications include dyld environment insertion, dylib hijacking, Mach task-port memory injection, Mach thread-state hijacking, ptrace manipulation, Mach exception-port redirection, reflective/memory-only Mach-O loading, and XPC dyld environment propagation. Definitions are versioned and deterministic. They describe observed technique compatibility, not attribution or confirmation of malicious intent.

An unmatched combination needs at least two meaningful process-manipulation signals before receiving a stable `MSAA-PI-UNKNOWN-<12 hexadecimal characters>` identifier. The identifier derives from normalized signals and source/target executable paths, allowing repeated observations to group without inventing a technique name. Analysts must investigate and may later map it to a reviewed named definition.

## Evidence preservation

The evidence plan recommends fixed Apple/macOS tools: `ps`, `codesign`, `vmmap`, `lsof`, `sample`, and bounded Unified Log review. The explicit snapshot collector uses argument arrays, fixed executable paths, timeouts, output limits, redaction, SHA-256 hashes, restrictive evidence-directory permissions, manifests, and custody-chain records. It does not load or execute the target.

PCAP collection is never automatic. If network evidence is material, an authorized analyst must approve the interface, narrow BPF host/port filter, duration, 96-byte default snap length, protected output location, classification, and retention. PID is not a BPF filter; endpoints must first be established from socket metadata. Full payload capture is discouraged.

Endpoint Security entitlement or another approved native sensor is required for reliable task/thread/memory provenance. Polling and `vmmap` snapshots can support investigation but cannot establish complete injection visibility.

# Event Schema

Events use `msaa.clickfix.event.v1` and contain identifiers, UTC time, phase, decision, mode, score, confidence, rule IDs, paste context, command SHA-256 and lengths, bounded shell/terminal metadata, versions, coverage, timing, and error code. They never contain command text, decoded text, URLs, working directories, environment contents, clipboard content, terminal output, or credentials.

User JSONL defaults to `~/Library/Logs/MSAA/clickfix-events.jsonl` with directory mode 0700 and file mode 0600. Appends use an exclusive advisory lock and one serialized write.

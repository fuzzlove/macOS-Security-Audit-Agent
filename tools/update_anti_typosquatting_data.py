#!/usr/bin/env python3
"""Developer-only official-data fetcher. It never runs at application startup."""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {"confusables": "https://www.unicode.org/Public/security/latest/confusables.txt"}
MAX_BYTES = 20_000_000


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=sorted(SOURCES), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True, help="Reviewed expected digest; prevents silently accepting mutable upstream data.")
    args = parser.parse_args(argv)
    url = SOURCES[args.source]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "www.unicode.org":
        raise SystemExit("source is not allowlisted")
    request = urllib.request.Request(url, headers={"User-Agent": "MSAA-Data-Update/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        if urllib.parse.urlsplit(response.geturl()).hostname != "www.unicode.org":
            raise SystemExit("unexpected redirect")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or b"confusables" not in raw[:4096].lower():
        raise SystemExit("unexpected source type or size")
    digest = hashlib.sha256(raw).hexdigest()
    if digest.lower() != args.expected_sha256.lower():
        raise SystemExit("source checksum did not match the reviewed expected digest")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = args.output_dir / "confusables.txt"
    target.write_bytes(raw)
    manifest = {"schema_version": "1.0", "source": url, "sha256": digest, "bytes": len(raw), "retrieved_at": datetime.now(timezone.utc).isoformat()}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Apple Silicon Build

Run natively on Apple Silicon:

```bash
uname -m  # must be arm64
scripts/build-arm64.sh
python3.12 scripts/generate_release_evidence.py --dist dist/arm64 --architecture arm64
```

The script rejects a translated process. Validate the app, helper selection, first-run paths, GUI, and degraded permissions on a clean Apple Silicon Mac.

# Intel Build

Run on a native Intel Mac or `macos-15-intel` CI runner:

```bash
uname -m  # must be x86_64
scripts/build-x86_64.sh
python3.12 scripts/generate_release_evidence.py --dist dist/x86_64 --architecture x86_64
```

Rosetta on Apple Silicon is test-only and is rejected by the release script. Validate on separate clean Intel hardware before publication.

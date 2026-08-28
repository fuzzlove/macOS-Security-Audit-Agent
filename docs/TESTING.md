# Testing

```bash
python3.12 -m compileall -q mac_audit_agent
python3.12 -m pytest -q
python3.12 -m build
python3.12 -m twine check dist/*
```

Release qualification additionally runs native arm64 and Intel builds, `file`, `lipo`, packaged doctor and GUI smoke tests, codesign verification, Gatekeeper assessment, hashes, SBOM/provenance generation, and clean-machine installation/removal tests. Mocked Rosetta/universal2 tests do not replace native hardware qualification.

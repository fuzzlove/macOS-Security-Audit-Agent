# MSAA Python Packaging Compatibility Matrix

Packaging support is narrower than source-runtime support. Import success or a CI job starting does not validate a release toolchain.

| Python | Source/test use | Packaging classification | Release policy |
|---|---|---|---|
| 3.12.x | Supported | Release baseline | Required release gate |
| 3.13.x | Candidate | Compatibility candidate | Non-release until complete matrix passes |
| 3.14.6 | Supported for qualified source tests | Experimental | Not a validated release packaging runtime |

Promotion requires clean dependency installation, `pip check`, unit tests, documentation integrity, two complete builds, Qt plugin and resource inventory, packaged executable smoke tests, GUI interaction, architecture validation, truthful signing assessment, and reproducibility comparison. Python 3.14 remains experimental until local and CI evidence from the same constraints passes all gates.

Build using the selected interpreter, never a global `pyinstaller` executable:

```bash
python3.12 -m venv /private/tmp/msaa-py312
/private/tmp/msaa-py312/bin/python -m pip install -r requirements-build.txt -r requirements-test.txt
/private/tmp/msaa-py312/bin/python scripts/build_pyinstaller.py --clean
```

Candidate builds additionally require `--experimental-runtime`. This flag permits measurement; it does not change the runtime classification.

## Local qualification evidence — 2026-07-10

- Python 3.12.13: two clean onedir builds passed. Both inventories contained 336 files with no path differences. Build manifests matched after excluding the intentionally unique build ID and timestamp. Both arm64 applications passed the offscreen main-window/Qt/help smoke test, AR022 resource hash comparison, and strict ad-hoc signature verification.
- Python 3.13: interpreter unavailable on the test host; not tested.
- Python 3.14.6: clean virtual-environment installation, `pip check`, focused tests, PyInstaller 6.21.0 build, arm64 architecture, Qt platform loading, main-window smoke, diagnostic resources, representative help topics, and strict ad-hoc signature verification passed. Gatekeeper assessment did not pass because the candidate is ad-hoc signed. CI reproduction and Developer ID release qualification remain outstanding, so the classification remains experimental.

The original Python 3.14.6 failure was not an upstream incompatibility: PyInstaller was simply absent from that interpreter environment. The first clean build-script attempt also exposed and fixed a source-checkout import-path defect and a missing noninteractive PyInstaller flag.

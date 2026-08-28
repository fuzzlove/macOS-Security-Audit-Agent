# Packaging and PyInstaller

## Python packages

Build from a clean checkout and an activated standard GIL-enabled Python 3.14 environment:

```bash
python -m pip install ".[build]"
python -m build
python -m twine check dist/*
```

For an offline development machine with compatible build requirements already installed, `python -m build --no-isolation` avoids downloads. Release builds should use normal isolated mode.

The wheel excludes tests, documentation sources, caches, reports, development identities/manifests, and icon source sets. It includes runtime Python modules, assets, the canonical integrity manifest/signature, trust policy, and public trust material. The measured wheel is 3.9 MB and the source distribution is 6.4 MB. `pyproject.toml` is the dependency source; `requirements.txt` is an editable contributor shortcut.

## Native application builds

PyInstaller does not cross-compile. Build macOS artifacts on macOS, and build separately on Apple silicon and Intel when both architectures are released.

```bash
python -m pip install ".[all,build]"
python scripts/build_pyinstaller.py --format onedir --clean
python scripts/build_pyinstaller.py --format onefile --clean
```

UPX is disabled. macOS application signing and notarization should be performed after PyInstaller assembly using the release process; ad-hoc signing during local builds is not a release signature.

## Measured comparison

Measurements were taken on macOS 15.7.2 arm64 with Python 3.12.13, PyInstaller 6.21.0, and PySide6 6.11.1. The workload was frozen `--doctor --json`, measured with `/usr/bin/time -l`. These are local engineering measurements, not claims for Intel or other macOS versions.

The source doctor itself completed in approximately 0.09 seconds during the same review. The frozen comparison measures bootstrap, interpreter, resource, and diagnostic startup; it is not a full GUI-render benchmark.

| Format | Artifact size | Compressed size | Startup | Maximum RSS | Resource result |
| --- | ---: | ---: | ---: | ---: | --- |
| One-directory `.app` | 118 MB | not measured | 1.17 s | 45.1 MB | assets and Office metadata passed |
| One-file executable | 47 MB | already compressed | 5.93 s | 52.3 MB | assets and Office metadata passed after `_MEIPASS` extraction |

The one-file build extracts into a random per-run temporary `_MEI...` directory. It was over five times slower for this small diagnostic workload, is harder to inspect, and PyInstaller 6.21 warns that one-file plus a macOS windowed `.app` conflicts with macOS security and will become an error in PyInstaller 7.

The recommended release format is therefore the signed and notarized one-directory `.app`, distributed as a ZIP or DMG. The one-file executable remains an explicit evaluation/debug option, not the default release format. One-directory also makes quarantine, signing, missing-library diagnosis, and incremental replacement clearer.

## Major size contributors

The largest final one-directory contributors were PySide6 (71 MB), lxml (8.6 MB), Python standard-library extensions (6.5 MB), the Python framework (5.8 MB), and OpenSSL `libcrypto` (4.7 MB). Office support adds openpyxl/python-docx plus lxml and is intentionally included in the desktop build.

Qt's dependency graph brings QtQml/QtQuick/QtPdf through the installed PySide6 build even though the spec uses narrow application imports. They were not manually excluded because doing so without a complete GUI regression run could break Qt plugins or transitive framework loading.

## Frozen behavior

- Python and PySide6 are bundled; users do not need Python.
- Data, cache, database, and logs remain outside the bundle in per-user locations.
- `multiprocessing.freeze_support()` runs before application dispatch.
- The maintained spec includes runtime data, the filename-loaded legacy framework module, and narrow hidden imports/metadata for `docx` and `openpyxl`.
- Frozen service plists invoke the stable installed MSAA executable with internal service flags; they contain no Homebrew Python, `python -m`, checkout path, or `PYTHONPATH`.
- Startup errors are logged and displayed through PySide6 when available, with a tkinter fallback where that standard-library component exists.
- `PKG001` tells users to reinstall the correct OS/architecture build and never recommends pip.

## Build validation and limitations

Python 3.12.13 successfully built both PyInstaller formats on macOS 15.7.2 arm64. Both frozen doctor runs found PySide6 6.11.1, openpyxl 3.1.5, python-docx 1.2.0, and all required assets without a separate Python runtime. The wheel (4.0 MB) and source distribution (6.4 MB) also built successfully using the declared backend.

The first isolated package build attempt could not reach PyPI from the sandbox. After explicit network approval, the normal isolated build completed. Twine validation and clean-wheel installation were not rerun in this repair pass and remain separate verification items.
# 2026-07-10 native packaging verification

The current dirty development tree was built natively on macOS 15.7.2 arm64 with Python 3.12.13 and PyInstaller 6.21.0. These are development measurements, not signed release artifacts.

| Artifact | Result | Size | SHA-256 | CLI startup | Peak RSS |
|---|---:|---:|---|---:|---:|
| Wheel | built and clean-installed | 4.0 MiB | `6ba4e767734b9eb17486a8852717608660d0f8256cb6defd8790d1481bc4a53f` | not measured | not measured |
| Sdist | built and clean-installed | 6.4 MiB | `ce4d196f98520ea550f8fda41dec4a2597c33b8d3abfa8365ad2732b975c4d61` | not measured | not measured |
| PyInstaller one-directory | CLI smoke passed | 118 MiB on disk | executable: `cf5a927f9b9803ed0736830581b849243ea5f835d9f214b1d82e3305f4cb0224` | 0.37 s | 58.8 MiB |
| PyInstaller one-file | CLI smoke passed outside sandbox | 47 MiB | `472cc48a9be7b533655a81908d608d9230c04d33f7bf26a01023d19af03625de` | 6.50–6.51 s | 58.4–59.2 MiB |

The one-file delay is dominated by extraction. PyInstaller warns that a one-file windowed macOS `.app` is deprecated and will become unsupported in PyInstaller 7; one-directory is therefore the preferred desktop format.

The build contained PySide6, python-docx, openpyxl, lxml, the declared integrity resources, and native arm64 binaries. It did not depend on an external Python during CLI smoke tests. Live GUI interaction, service installation, codesigning, notarization, and separate bundled monitor/notifier helpers were not verified.

Startup measurements used `/usr/bin/time -l <artifact> --help`. Peak RSS is the reported maximum resident set size. Full GUI, Safe Scan, persistence, rootkit, and exporter RSS measurements remain outstanding.

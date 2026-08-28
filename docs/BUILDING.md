# Building

Create an isolated Python 3.12 environment and install pinned build inputs:

```bash
python3.12 -m venv .venv-build
. .venv-build/bin/activate
python -m pip install -U pip
python -m pip install -r requirements-build.txt -r requirements-test.txt
scripts/build-wheel.sh
scripts/build-sdist.sh
```

PyInstaller builds are native, not cross-compiled. Use the architecture-specific scripts on matching native hardware. `MACOSX_DEPLOYMENT_TARGET` defaults to the documented macOS 12 policy. Build commands fail when architecture prerequisites are false.

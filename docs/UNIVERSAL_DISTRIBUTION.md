# Universal Distribution

The production strategy is native dual builds: arm64 on Apple Silicon and x86_64 on Intel. Publish explicitly named ZIP/DMG artifacts plus shared Python wheel/sdist, hashes, manifest, SBOM, and provenance.

`scripts/build-universal.sh` is fail-closed. It proceeds only with a universal2 Python and `scripts/verify-architectures.sh` rejects any embedded single-slice Mach-O. Two unrelated app bundles are never concatenated or called universal2.

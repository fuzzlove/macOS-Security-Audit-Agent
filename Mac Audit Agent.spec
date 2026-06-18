# -*- mode: python ; coding: utf-8 -*-

datas = [
    ('mac_audit_agent/assets', 'mac_audit_agent/assets'),
    ('README.md', '.'),
    ('LICENSE', '.'),
    ('SECURITY.md', '.'),
    ('CONTRIBUTING.md', '.'),
    ('CODE_OF_CONDUCT.md', '.'),
    ('CHANGELOG.md', '.'),
    ('docs', 'docs'),
]
binaries = []
hiddenimports = []


a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Mac Audit Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='universal2',
    codesign_identity=None,
    entitlements_file=None,
    icon=['mac_audit_agent/assets/app_icon.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Mac Audit Agent',
)
app = BUNDLE(
    coll,
    name='Mac Audit Agent.app',
    icon='mac_audit_agent/assets/app_icon.icns',
    bundle_identifier='com.fuzzlove.macos-security-audit-agent',
    version='0.1.1',
    info_plist={
        'CFBundleVersion': '0.1.1',
    },
)

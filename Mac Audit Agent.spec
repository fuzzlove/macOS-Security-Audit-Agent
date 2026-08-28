# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys
import os
from importlib.metadata import PackageNotFoundError
from PyInstaller.utils.hooks import collect_data_files, copy_metadata
from PyInstaller.building.datastruct import Tree

PROJECT_ROOT = Path(SPECPATH).resolve()
TARGET_ARCH = os.environ.get('MSAA_TARGET_ARCH') or None
CODESIGN_IDENTITY = os.environ.get('MSAA_CODESIGN_IDENTITY') or None
ENTITLEMENTS_FILE = os.environ.get('MSAA_APP_ENTITLEMENTS') or None
sys.path.insert(0, str(PROJECT_ROOT))

# Runtime data only. Analysis discovers Python modules; copying the entire
# package would duplicate modules and ship tests and caches.
datas = collect_data_files('mac_audit_agent', includes=[
    'assets/*',
    'assets/ransomware/*.json',
    'assets/licensing/*.json',
    'assets/vulnerability/*.json',
    'help/resources/**/*.md',
    'integrity/integrity_manifest.json',
    'integrity/integrity_manifest.signature.json',
    'integrity/trust_policy.json',
    'integrity/trust/*.pem',
    'anti_typosquatting/*.json',
    'config/*.json',
    'security/lockdown/lockdown_profiles/*.json',
])
# frameworks/__init__.py deliberately loads this legacy sibling by filename.
datas.append(('mac_audit_agent/frameworks.py', 'mac_audit_agent'))
build_manifest = os.environ.get('MSAA_BUILD_MANIFEST', '')
if build_manifest and Path(build_manifest).is_file():
    datas.append((build_manifest, 'mac_audit_agent'))
clickfix_agent_app = os.environ.get('MSAA_CLICKFIX_AGENT_APP', '')
if clickfix_agent_app and Path(clickfix_agent_app).is_dir():
    datas += Tree(clickfix_agent_app, prefix='Library/LoginItems/MSAAClickFixGuardAgent.app')
for distribution in ('PySide6', 'shiboken6', 'openpyxl', 'python-docx', 'PyYAML', 'cryptography', 'yara-python'):
    try:
        datas += copy_metadata(distribution)
    except PackageNotFoundError:
        # Optional features remain excluded when their distribution is absent.
        pass

a = Analysis(
    ['launcher.py'],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=['mac_audit_agent.integrity.__main__', 'docx', 'openpyxl', 'yara'],
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
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=TARGET_ARCH,
    codesign_identity=CODESIGN_IDENTITY,
    entitlements_file=ENTITLEMENTS_FILE,
    icon=['mac_audit_agent/assets/app_icon.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='Mac Audit Agent',
)
app = BUNDLE(
    coll,
    name='Mac Audit Agent.app',
    icon='mac_audit_agent/assets/app_icon.icns',
    bundle_identifier='com.fuzzlove.macos-security-audit-agent',
    version='1.0b',
    info_plist={
        'CFBundleShortVersionString': '1.0b',
        'CFBundleVersion': '1.0b',
        'NSHumanReadableCopyright': 'MSAA local defensive security application',
    },
)

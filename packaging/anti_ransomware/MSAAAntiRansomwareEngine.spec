from pathlib import Path
root=Path(SPECPATH).parents[1]
a=Analysis([str(root/'mac_audit_agent/anti_ransomware/system_engine_entry.py')],pathex=[str(root)],binaries=[],datas=[],hiddenimports=['mac_audit_agent.anti_ransomware.containment_diagnostics'],hookspath=[],runtime_hooks=[],excludes=['PySide6','PyQt6','tkinter'],noarchive=False)
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,[],exclude_binaries=True,name='MSAAAntiRansomwareEngine',debug=False,bootloader_ignore_signals=False,strip=False,upx=False,console=True)
coll=COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='MSAAAntiRansomwareEngine')

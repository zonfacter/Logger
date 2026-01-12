# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Logger_rs232.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Anwendungens\\Python314\\tcl\\tcl8.6', 'tcl'), ('C:\\Anwendungens\\Python314\\tcl\\tk8.6', 'tk')],
    hiddenimports=[],
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
    a.binaries,
    a.datas,
    [],
    name='Logger_rs232',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

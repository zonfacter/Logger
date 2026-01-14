# -*- mode: python ; coding: utf-8 -*-
"""
RS485 Sniffer v1.6.1 - PyInstaller Spec File
=============================================

Build Instructions:
1. Install PyInstaller: pip install pyinstaller
2. Place this file in the same folder as rs485_sniffer_v1.6.1.py
3. Run: pyinstaller rs485_sniffer_v1.6.1.spec
4. Find EXE in: dist/RS485_Sniffer/

For single-file EXE (slower startup):
    Change: onefile=True in EXE() section
"""

import sys
from pathlib import Path

block_cipher = None

# Collect all plugin files
plugin_datas = []
plugins_path = Path('plugins')
if plugins_path.exists():
    for plugin_dir in plugins_path.iterdir():
        if plugin_dir.is_dir():
            for py_file in plugin_dir.glob('*.py'):
                # (source, destination_folder)
                plugin_datas.append((str(py_file), f'plugins/{plugin_dir.name}'))

a = Analysis(
    ['rs485_sniffer_v1.6.1.py'],
    pathex=[],
    binaries=[],
    datas=plugin_datas,  # Include plugins
    hiddenimports=[
        'serial',
        'serial.tools',
        'serial.tools.list_ports',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'logging',
        'threading',
        'queue',
        'json',
        'csv',
        'dataclasses',
        'typing',
        'pathlib',
        'datetime',
        're',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
        'tensorflow',
        'torch',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='RS485_Sniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # False = keine Konsole (GUI-App)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Optional: 'icon.ico' für eigenes Icon
    version=None,  # Optional: 'version_info.txt' für Versionsinformationen
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='RS485_Sniffer',
)

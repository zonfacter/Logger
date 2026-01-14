# -*- mode: python ; coding: utf-8 -*-
"""
RS485 Sniffer v1.5.1 - PyInstaller Spec File
Build: pyinstaller rs485_sniffer.spec
"""

import os

block_cipher = None

# SPECPATH is the directory containing THIS .spec file
# All paths are relative to where the .spec file is located
SPEC_DIR = SPECPATH

# Main script - in the SAME directory as the .spec file
main_script = os.path.join(SPEC_DIR, 'rs485_sniffer_v1.5.1.py')

a = Analysis(
    [main_script],
    pathex=[SPEC_DIR],
    binaries=[],
    datas=[
        # Include plugin_api.py (relative to SPEC_DIR)
        (os.path.join(SPEC_DIR, 'plugin_api.py'), '.'),
    ],
    hiddenimports=[
        'serial',
        'serial.tools',
        'serial.tools.list_ports',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'json',
        'queue',
        'threading',
        'datetime',
        'collections',
        'dataclasses',
        'abc',
        'importlib',
        'importlib.util',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'numpy', 'pandas', 'scipy',
        'PIL', 'cv2', 'tensorflow', 'torch',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Directory Build (recommended)
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
    console=False,  # True for debug output
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
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

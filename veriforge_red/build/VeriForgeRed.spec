# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for VeriForge Red.

Builds two executables:
  1. VeriForgeRed.exe      — Desktop GUI app (windowed)
  2. VeriForgeRedService.exe — Background service (console)

Usage:
    pyinstaller veriforge_red/build/VeriForgeRed.spec
"""

import os
from pathlib import Path

# ── Project layout ──────────────────────────────────────────────────────────
PROJECT_ROOT = Path(SPECPATH).resolve().parent.parent  # repo root
BUILD_DIR = PROJECT_ROOT / "veriforge_red" / "build"
DIST_DIR = BUILD_DIR / "dist"
ICON_PATH = BUILD_DIR / "icon.ico"

# Ensure icon exists
if not ICON_PATH.exists():
    from PIL import Image, ImageDraw, ImageFont
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    def _shield(cx, cy, sz, color):
        h = sz // 2
        draw.polygon([
            (cx - h + 4, cy - h + 8), (cx - h + 4, cy + 4), (cx, cy + h - 4),
            (cx + h - 4, cy + 4), (cx + h - 4, cy - h + 8), (cx, cy - h),
        ], fill=color)
    _shield(size // 2, size // 2, size - 8, "#8b0000")
    _shield(size // 2, size // 2, size - 18, "#c62828")
    _shield(size // 2, size // 2 - 2, size - 30, "#e94560")
    try:
        font = ImageFont.truetype("segoeui.ttf", size // 3)
    except OSError:
        font = ImageFont.load_default()
    text = "V"
    bbox = draw.textbbox((0, 0), text, font=font)
    draw.text(((size - (bbox[2] - bbox[0])) // 2 - bbox[0],
               (size - (bbox[3] - bbox[1])) // 2 - bbox[1] - 2),
              text, fill="#ffffff", font=font)
    img.save(ICON_PATH, "ICO")

# ── Hidden imports ──────────────────────────────────────────────────────────
HIDDEN_IMPORTS = [
    # veriforge_red core
    "veriforge_red.core.engine",
    "veriforge_red.core.scanner",
    "veriforge_red.core.privacy",
    "veriforge_red.core.threats",
    "veriforge_red.core.quarantine",
    "veriforge_red.core.remediation",
    "veriforge_red.core.vault",
    "veriforge_red.core.database",
    "veriforge_red.core.monitor",
    # desktop modules
    "veriforge_red.desktop.app",
    "veriforge_red.desktop.tray",
    "veriforge_red.desktop.service",
    # windows modules
    "veriforge_red.windows.privacy",
    # PIL / pystray
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL.ImageFont",
    "pystray",
    # pywin32
    "win32service",
    "win32serviceutil",
    "win32event",
    "servicemanager",
    # crypto
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    # templating / watching
    "jinja2",
    "jinja2.runtime",
    "watchdog",
    "watchdog.observers",
    "watchdog.events",
    # WMI
    "wmi",
    # Windows stdlib
    "winreg",
    "ctypes",
    "ctypes.wintypes",
]

# ── Analysis ────────────────────────────────────────────────────────────────
# Desktop app entry point
entry_desktop = str(PROJECT_ROOT / "veriforge_red" / "desktop" / "__main__.py")
if not os.path.exists(entry_desktop):
    # Fallback: create a temporary entry point
    entry_desktop = str(BUILD_DIR / "_desktop_entry.py")
    with open(entry_desktop, "w") as f:
        f.write('''
from veriforge_red.desktop.tray import run_with_tray
from veriforge_red.desktop.app import RedApp
if __name__ == "__main__":
    app = RedApp()
    run_with_tray(app)
''')

a_desktop = Analysis(
    [entry_desktop],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "veriforge_red" / "core"), "veriforge_red/core"),
        (str(PROJECT_ROOT / "veriforge_red" / "windows"), "veriforge_red/windows"),
    ],
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

# Service entry point
entry_service = str(PROJECT_ROOT / "veriforge_red" / "desktop" / "service.py")

a_service = Analysis(
    [entry_service],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "veriforge_red" / "core"), "veriforge_red/core"),
        (str(PROJECT_ROOT / "veriforge_red" / "windows"), "veriforge_red/windows"),
    ],
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

# Shared PYZ & EXE settings
pyz_desktop = PYZ(a_desktop.pure, a_desktop.zipped_data, cipher=None)
pyz_service = PYZ(a_service.pure, a_service.zipped_data, cipher=None)

exe_desktop = EXE(
    pyz_desktop,
    a_desktop.scripts,
    a_desktop.binaries,
    a_desktop.zipfiles,
    a_desktop.datas,
    [],
    name="VeriForgeRed",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # windowed — no console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_PATH),
)

exe_service = EXE(
    pyz_service,
    a_service.scripts,
    a_service.binaries,
    a_service.zipfiles,
    a_service.datas,
    [],
    name="VeriForgeRedService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # console — for service
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_PATH),
)

# Collect into dist
coll = COLLECT(
    exe_desktop,
    exe_service,
    name="VeriForgeRed",
)

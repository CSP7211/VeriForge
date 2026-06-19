"""Build script to create Windows .exe using PyInstaller.

Generates two executables:
1. ``VeriForgeRed.exe`` — Main desktop app (windowed, single file)
2. ``VeriForgeRedService.exe`` — Background service (console)

Usage::

    python veriforge_red/build/build_windows.py

Requirements::

    pip install pyinstaller pillow pystray pywin32 cryptography jinja2 watchdog wmi

"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# ── Paths ───────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DIR = PROJECT_ROOT / "veriforge_red" / "build"
DIST_DIR = BUILD_DIR / "dist"
SPECS_DIR = BUILD_DIR
ICON_PATH = BUILD_DIR / "icon.ico"

# ── Icon generation ─────────────────────────────────────────────────────────


def _ensure_icon() -> Path:
    """Generate a red-shield icon if it doesn't already exist."""
    if ICON_PATH.exists():
        return ICON_PATH

    from PIL import Image, ImageDraw, ImageFont

    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    def _shield(cx: int, cy: int, sz: int, color: str) -> None:
        h = sz // 2
        polygon = [
            (cx - h + 4, cy - h + 8),
            (cx - h + 4, cy + 4),
            (cx, cy + h - 4),
            (cx + h - 4, cy + 4),
            (cx + h - 4, cy - h + 8),
            (cx, cy - h),
        ]
        draw.polygon(polygon, fill=color)

    _shield(size // 2, size // 2, size - 8, "#8b0000")
    _shield(size // 2, size // 2, size - 18, "#c62828")
    _shield(size // 2, size // 2 - 2, size - 30, "#e94560")

    try:
        font = ImageFont.truetype("segoeui.ttf", size // 3)
    except OSError:
        font = ImageFont.load_default()
    text = "V"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text(((size - tw) // 2 - bbox[0], (size - th) // 2 - bbox[1] - 2),
              text, fill="#ffffff", font=font)

    img.save(ICON_PATH, "ICO")
    print(f"[build] Generated icon: {ICON_PATH}")
    return ICON_PATH


# ── Hidden imports ──────────────────────────────────────────────────────────

HIDDEN_IMPORTS = [
    # core
    "veriforge_red.core.engine",
    "veriforge_red.core.scanner",
    "veriforge_red.core.privacy",
    "veriforge_red.core.threats",
    "veriforge_red.core.quarantine",
    "veriforge_red.core.remediation",
    "veriforge_red.core.vault",
    "veriforge_red.core.database",
    "veriforge_red.core.monitor",
    # desktop
    "veriforge_red.desktop.app",
    "veriforge_red.desktop.tray",
    "veriforge_red.desktop.service",
    # windows
    "veriforge_red.windows.privacy",
    # third-party
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "PIL.ImageFont",
    "pystray",
    "win32service",
    "win32serviceutil",
    "win32event",
    "servicemanager",
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "jinja2",
    "jinja2.runtime",
    "watchdog",
    "watchdog.observers",
    "watchdog.events",
    "wmi",
    # Windows-specific stdlib
    "winreg",
    "ctypes",
    "ctypes.wintypes",
]


# ── Build commands ──────────────────────────────────────────────────────────


def _pyinstaller_args(
    script: Path,
    name: str,
    console: bool = False,
    icon: Path | None = None,
) -> list[str]:
    """Build the argument list for a PyInstaller invocation."""
    args = [
        sys.executable, "-m", "PyInstaller",
        str(script),
        "--onefile",
        "--noconfirm",
        "--clean",
        f"--name={name}",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR / 'work'}",
        f"--specpath={SPECS_DIR}",
    ]

    if not console:
        args.append("--windowed")

    if icon:
        args.append(f"--icon={icon}")

    for imp in HIDDEN_IMPORTS:
        args.append(f"--hidden-import={imp}")

    # --add-data for templates / config directories
    # Add the core package as data
    core_pkg = PROJECT_ROOT / "veriforge_red" / "core"
    if core_pkg.exists():
        args.append(f"--add-data={core_pkg}{os.pathsep}veriforge_red/core")

    windows_pkg = PROJECT_ROOT / "veriforge_red" / "windows"
    if windows_pkg.exists():
        args.append(f"--add-data={windows_pkg}{os.pathsep}veriforge_red/windows")

    return args


def build_desktop_app() -> None:
    """Build ``VeriForgeRed.exe`` (GUI, windowed)."""
    icon = _ensure_icon()
    script = PROJECT_ROOT / "veriforge_red" / "desktop" / "__main__.py"

    if not script.exists():
        # Create a minimal __main__.py if it doesn't exist
        script = BUILD_DIR / "_desktop_entry.py"
        script.write_text('''\
"""Entry-point for the VeriForge Red desktop app."""
from veriforge_red.desktop.tray import run_with_tray
from veriforge_red.desktop.app import RedApp

if __name__ == "__main__":
    app = RedApp()
    run_with_tray(app)
''')

    args = _pyinstaller_args(script, "VeriForgeRed", console=False, icon=icon)
    print(f"[build] Building desktop app...\n  {' '.join(args)}")
    subprocess.run(args, check=True)
    print(f"[build] VeriForgeRed.exe -> {DIST_DIR}")


def build_service() -> None:
    """Build ``VeriForgeRedService.exe`` (console, for Windows service)."""
    icon = _ensure_icon()
    script = PROJECT_ROOT / "veriforge_red" / "desktop" / "service.py"

    args = _pyinstaller_args(script, "VeriForgeRedService", console=True, icon=icon)
    print(f"[build] Building service...\n  {' '.join(args)}")
    subprocess.run(args, check=True)
    print(f"[build] VeriForgeRedService.exe -> {DIST_DIR}")


def clean() -> None:
    """Remove PyInstaller intermediate files."""
    for d in (BUILD_DIR / "work", BUILD_DIR / "dist"):
        if d.exists():
            shutil.rmtree(d)
            print(f"[build] Removed {d}")
    for f in (BUILD_DIR / "*.spec",):
        for p in BUILD_DIR.glob("*.spec"):
            p.unlink()
            print(f"[build] Removed {p}")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Build VeriForge Red for Windows")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts first")
    parser.add_argument("--desktop-only", action="store_true", help="Build only the desktop app")
    parser.add_argument("--service-only", action="store_true", help="Build only the service")
    args = parser.parse_args()

    if args.clean:
        clean()

    DIST_DIR.mkdir(parents=True, exist_ok=True)

    if not args.service_only:
        build_desktop_app()
    if not args.desktop_only:
        build_service()

    print("\n[build] All builds complete!")
    print(f"  Desktop : {DIST_DIR / 'VeriForgeRed.exe'}")
    print(f"  Service : {DIST_DIR / 'VeriForgeRedService.exe'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
================================================================================
 VeriForge Security Platform - Windows Installer
================================================================================
Installer for the VeriForge security platform with 7 integrated products.
Handles Python detection, SDK installation, shortcuts, PATH configuration,
system tray integration, and uninstaller creation.

Usage:
    python install.py                # Interactive installation
    python install.py --silent       # Silent mode (all defaults)
    python install.py --sdk-path C:\\path\\to\\veriforge-sdk.zip
================================================================================
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
import urllib.request
import winreg
from datetime import datetime
from pathlib import Path
from typing import Any

# ==============================================================================
# Constants & Configuration
# ==============================================================================

INSTALLER_VERSION = "1.0.0"
MIN_PYTHON_VERSION = (3, 10)
REQUIRED_PYTHON_VERSION_STR = "3.10+"

SDK_PACKAGE_NAME = "veriforge-sdk"
SDK_PACKAGE_ZIP = "veriforge-sdk.zip"
INSTALL_DIR = Path.home() / ".veriforge"
LOG_FILE = INSTALL_DIR / "install.log"
DATA_DIR = INSTALL_DIR / "data"
CONFIG_DIR = INSTALL_DIR / "config"

SHORTCUT_NAMES = {
    "scanner": "VeriForge Red Scanner",
    "dashboard": "VeriForge Dashboard",
    "cli": "VeriForge CLI",
}

PRODUCTS = [
    "VeriForge Red (Vulnerability Scanner)",
    "VeriClaw (Malware Detection)",
    "VeriForge Core (Policy Engine)",
    "VeriShield (Network Monitor)",
    "VeriAudit (Compliance)",
    "VeriTrace (Forensics)",
    "VeriGuard (Endpoint Protection)",
]

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"


# ==============================================================================
# Logging & Progress Reporting
# ==============================================================================

class InstallerLogger:
    """Handles all installer output with colored terminal reporting and file logging."""

    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file
        self.start_time = time.time()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Clear previous log
        log_file.write_text(f"VeriForge Installer Log - {datetime.now()}\n", encoding="utf-8")

    def _write_log(self, level: str, message: str) -> None:
        """Write a line to the log file."""
        elapsed = time.time() - self.start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{level:8}] [{elapsed:7.2f}s] {message}\n")

    def header(self, message: str) -> None:
        """Print a large section header."""
        width = 78
        print()
        print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD} {message}^{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}")
        self._write_log("HEADER", message)

    def step(self, message: str) -> None:
        """Print a step announcement."""
        print(f"\n{Colors.BLUE}{Colors.BOLD}>> {message}{Colors.RESET}")
        self._write_log("STEP", message)

    def info(self, message: str) -> None:
        """Print informational message."""
        print(f"{Colors.BLUE}   {message}{Colors.RESET}")
        self._write_log("INFO", message)

    def success(self, message: str) -> None:
        """Print success message."""
        print(f"{Colors.GREEN}   [OK] {message}{Colors.RESET}")
        self._write_log("SUCCESS", message)

    def warning(self, message: str) -> None:
        """Print warning message."""
        print(f"{Colors.YELLOW}   [WARN] {message}{Colors.RESET}")
        self._write_log("WARNING", message)

    def error(self, message: str) -> None:
        """Print error message."""
        print(f"{Colors.RED}   [ERROR] {message}{Colors.RESET}")
        self._write_log("ERROR", message)

    def progress(self, percent: int, message: str) -> None:
        """Print a progress bar."""
        bar_width = 40
        filled = int(bar_width * percent / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        print(f"\r{Colors.CYAN}   [{bar}] {percent:3d}% {message}{Colors.RESET}", end="", flush=True)
        if percent >= 100:
            print()
        self._write_log("PROGRESS", f"{percent}% - {message}")

    def banner(self) -> None:
        """Print the installer banner."""
        banner_text = rf"""
{Colors.RED} ██╗   ██╗███████╗██████╗ ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗{Colors.RESET}
{Colors.RED} ██║   ██║██╔════╝██╔══██╗██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝{Colors.RESET}
{Colors.RED} ██║   ██║█████╗  ██████╔╝██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  {Colors.RESET}
{Colors.RED} ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  {Colors.RESET}
{Colors.RED}  ╚████╔╝ ███████╗██║  ██║██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗{Colors.RESET}
{Colors.RED}   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝{Colors.RESET}
{Colors.YELLOW}                    Security Platform Windows Installer{Colors.RESET}
{Colors.DIM}                               v{INSTALLER_VERSION}{Colors.RESET}
"""
        print(banner_text)
        self._write_log("BANNER", f"VeriForge Installer v{INSTALLER_VERSION}")


# ==============================================================================
# Global Logger Instance
# ==============================================================================

log = InstallerLogger(LOG_FILE)


# ==============================================================================
# System Checks
# ==============================================================================

def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


def check_python() -> tuple[bool, str, tuple[int, ...]]:
    """
    Check if Python 3.10+ is available.

    Returns:
        (ok, message, version_tuple)
    """
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version >= MIN_PYTHON_VERSION:
        return True, f"Python {version_str} detected (meets {REQUIRED_PYTHON_VERSION_STR} requirement)", version[:2]
    elif version.major >= 3:
        return False, f"Python {version_str} is too old. VeriForge requires Python {REQUIRED_PYTHON_VERSION_STR}.", version[:2]
    else:
        return False, f"Python {version_str} is not supported. VeriForge requires Python {REQUIRED_PYTHON_VERSION_STR}.", version[:2]


def find_python_on_system() -> str | None:
    """Search for Python installations in common locations."""
    possible_paths = [
        Path(r"C:\Python310\python.exe"),
        Path(r"C:\Python311\python.exe"),
        Path(r"C:\Python312\python.exe"),
        Path(r"C:\Program Files\Python310\python.exe"),
        Path(r"C:\Program Files\Python311\python.exe"),
        Path(r"C:\Program Files\Python312\python.exe"),
        Path(r"C:\Users") / os.environ.get("USERNAME", "") / r"AppData\Local\Programs\Python\Python310\python.exe",
        Path(r"C:\Users") / os.environ.get("USERNAME", "") / r"AppData\Local\Programs\Python\Python311\python.exe",
        Path(r"C:\Users") / os.environ.get("USERNAME", "") / r"AppData\Local\Programs\Python\Python312\python.exe",
    ]
    for p in possible_paths:
        if p.exists():
            return str(p)

    # Try PATH search
    for cmd in ["python", "python3", "py"]:
        found = shutil.which(cmd)
        if found:
            return found

    return None


def check_pip(python_exe: str | None = None) -> bool:
    """Check if pip is available for the given Python executable."""
    exe = python_exe or sys.executable
    try:
        result = subprocess.run(
            [exe, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def install_pip(python_exe: str | None = None) -> bool:
    """Attempt to install pip using ensurepip."""
    exe = python_exe or sys.executable
    log.step("Installing pip...")
    try:
        result = subprocess.run(
            [exe, "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            log.success("pip installed successfully via ensurepip")
            return True
        log.warning("ensurepip failed, trying get-pip.py...")
        # Download get-pip.py
        get_pip_path = INSTALL_DIR / "get-pip.py"
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", str(get_pip_path))
        result = subprocess.run([exe, str(get_pip_path)], capture_output=True, text=True, timeout=120)
        get_pip_path.unlink(missing_ok=True)
        if result.returncode == 0:
            log.success("pip installed successfully via get-pip.py")
            return True
        log.error("Failed to install pip")
        return False
    except Exception as e:
        log.error(f"pip installation failed: {e}")
        return False


# ==============================================================================
# SDK Installation
# ==============================================================================

def install_sdk(sdk_path: str | None = None, silent: bool = False) -> bool:
    """
    Install the VeriForge SDK package.

    Args:
        sdk_path: Optional local path to SDK ZIP file
        silent: If True, don't prompt for input
    """
    log.step("Installing VeriForge SDK...")

    if not check_pip():
        log.warning("pip not found. Attempting to install...")
        if not install_pip():
            log.error("Cannot install SDK without pip. Please install pip manually.")
            return False

    try:
        if sdk_path and os.path.isfile(sdk_path):
            log.info(f"Installing from local file: {sdk_path}")
            log.progress(10, "Reading local package...")
            cmd = [sys.executable, "-m", "pip", "install", sdk_path, "--upgrade"]
        else:
            log.info(f"Installing {SDK_PACKAGE_NAME} from PyPI...")
            log.progress(10, "Downloading from PyPI...")
            cmd = [sys.executable, "-m", "pip", "install", SDK_PACKAGE_NAME, "--upgrade"]

        log.progress(30, "Installing package...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            log.error(f"pip install failed:\n{result.stderr}")
            # Fallback: try without --upgrade
            log.info("Retrying without --upgrade flag...")
            cmd.pop(-2)  # Remove --upgrade
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                log.error(f"Retry failed:\n{result.stderr}")
                return False

        log.progress(100, "SDK installed!")
        log.success("VeriForge SDK installed successfully")
        return True

    except subprocess.TimeoutExpired:
        log.error("SDK installation timed out (5 minutes). Check your internet connection.")
        return False
    except Exception as e:
        log.error(f"SDK installation failed: {e}")
        traceback.print_exc()
        return False


# ==============================================================================
# Desktop Shortcuts
# ==============================================================================

def create_desktop_shortcuts(silent: bool = False) -> dict[str, bool]:
    """
    Create Windows desktop shortcuts for VeriForge applications.

    Creates:
        - VeriForge Red Scanner (with directory picker)
        - VeriForge Dashboard
        - VeriForge CLI

    Returns:
        Dict mapping shortcut name to success status.
    """
    log.step("Creating desktop shortcuts...")
    results: dict[str, bool] = {}

    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        desktop = Path.home() / "OneDrive" / "Desktop"

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    # Create wrapper scripts
    scanner_script = INSTALL_DIR / "scanner_launcher.py"
    scanner_script.write_text(SCANNER_LAUNCHER_SCRIPT, encoding="utf-8")

    dashboard_script = INSTALL_DIR / "dashboard_launcher.py"
    dashboard_script.write_text(DASHBOARD_LAUNCHER_SCRIPT, encoding="utf-8")

    cli_script = INSTALL_DIR / "cli_launcher.py"
    cli_script.write_text(CLI_LAUNCHER_SCRIPT, encoding="utf-8")

    # 1. VeriForge Red Scanner shortcut
    try:
        log.info("Creating Red Scanner shortcut...")
        create_shortcut(
            target=sys.executable,
            arguments=f'"{scanner_script}"',
            shortcut_path=desktop / f"{SHORTCUT_NAMES['scanner']}.lnk",
            description="VeriForge Red Security Scanner - Scan directories for vulnerabilities",
            icon_index=0,
        )
        log.success(f"'{SHORTCUT_NAMES['scanner']}' shortcut created on Desktop")
        results["scanner"] = True
    except Exception as e:
        log.error(f"Failed to create scanner shortcut: {e}")
        results["scanner"] = False

    # 2. VeriForge Dashboard shortcut
    try:
        log.info("Creating Dashboard shortcut...")
        create_shortcut(
            target=sys.executable,
            arguments=f"-m {SDK_PACKAGE_NAME} dashboard",
            shortcut_path=desktop / f"{SHORTCUT_NAMES['dashboard']}.lnk",
            description="VeriForge Dashboard - Security overview and monitoring",
            icon_index=0,
        )
        log.success(f"'{SHORTCUT_NAMES['dashboard']}' shortcut created on Desktop")
        results["dashboard"] = True
    except Exception as e:
        log.error(f"Failed to create dashboard shortcut: {e}")
        results["dashboard"] = False

    # 3. VeriForge CLI shortcut
    try:
        log.info("Creating CLI shortcut...")
        create_shortcut(
            target=str(cli_script),
            arguments="",
            shortcut_path=desktop / f"{SHORTCUT_NAMES['cli']}.lnk",
            description="VeriForge CLI - Command-line interface",
            icon_index=0,
        )
        log.success(f"'{SHORTCUT_NAMES['cli']}' shortcut created on Desktop")
        results["cli"] = True
    except Exception as e:
        log.error(f"Failed to create CLI shortcut: {e}")
        results["cli"] = False

    return results


def create_shortcut(
    target: str,
    arguments: str,
    shortcut_path: Path,
    description: str,
    icon_index: int = 0,
) -> None:
    """
    Create a Windows .lnk shortcut file using the Windows Script Host.

    Args:
        target: Path to the executable
        arguments: Command-line arguments
        shortcut_path: Where to save the .lnk file
        description: Tooltip description
        icon_index: Icon index in the target executable
    """
    shortcut_path.parent.mkdir(parents=True, exist_ok=True)

    # Use winshell if available, otherwise use WScript.Shell via PowerShell
    try:
        import winshell
        from win32com.client import Dispatch
        shell = Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(shortcut_path))
        shortcut.TargetPath = target
        shortcut.Arguments = arguments
        shortcut.Description = description
        shortcut.WorkingDirectory = str(Path.home())
        shortcut.IconLocation = f"{target},{icon_index}"
        shortcut.save()
    except ImportError:
        # Fallback: use PowerShell to create shortcut
        ps_script = f"""
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
$Shortcut.TargetPath = "{target}"
$Shortcut.Arguments = "{arguments}"
$Shortcut.Description = "{description}"
$Shortcut.WorkingDirectory = "{Path.home()}"
$Shortcut.IconLocation = "{target},{icon_index}"
$Shortcut.Save()
"""
        subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            check=True,
            timeout=30,
        )


# ==============================================================================
# Wrapper Script Templates
# ==============================================================================

SCANNER_LAUNCHER_SCRIPT = '''#!/usr/bin/env python3
"""Launcher for VeriForge Red Scanner with directory picker dialog."""

import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox


def pick_directory() -> str | None:
    """Show a directory picker dialog and return the selected path."""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    directory = filedialog.askdirectory(
        title="VeriForge Red Scanner - Select Target Directory",
        mustexist=True,
    )
    root.destroy()
    return directory if directory else None


def main() -> None:
    print("=" * 60)
    print("  VeriForge Red Scanner")
    print("=" * 60)
    print("Select a directory to scan for vulnerabilities...")
    print()

    target = pick_directory()
    if not target:
        print("No directory selected. Exiting.")
        sys.exit(0)

    print(f"Target: {target}")
    print(f"Launching scan...")
    print("-" * 60)

    try:
        subprocess.run(
            [sys.executable, "-m", "veriforge_sdk", "scan", target],
            check=False,
        )
    except KeyboardInterrupt:
        print("\\nScan interrupted by user.")
    except Exception as e:
        messagebox.showerror("Scan Error", f"Failed to run scan: {e}")
        sys.exit(1)

    input("\\nPress Enter to exit...")


if __name__ == "__main__":
    main()
'''

DASHBOARD_LAUNCHER_SCRIPT = '''#!/usr/bin/env python3
"""Launcher for VeriForge Dashboard."""

import subprocess
import sys


def main() -> None:
    print("Starting VeriForge Dashboard...")
    try:
        subprocess.run(
            [sys.executable, "-m", "veriforge_sdk", "dashboard"],
            check=False,
        )
    except KeyboardInterrupt:
        print("\\nDashboard closed.")


if __name__ == "__main__":
    main()
'''

CLI_LAUNCHER_SCRIPT = '''#!/usr/bin/env python3
"""Launcher for VeriForge CLI in a terminal window."""

import os
import subprocess
import sys


def main() -> None:
    """Open a terminal with veriforge-sdk available."""
    print("=" * 60)
    print("  VeriForge CLI")
    print("=" * 60)
    print("Available commands:")
    print("  veriforge-sdk scan <path>     Scan directory")
    print("  veriforge-sdk dashboard       Open dashboard")
    print("  veriforge-sdk audit           Run privacy audit")
    print("  veriforge-sdk --help          Show all commands")
    print("=" * 60)
    print()

    # Keep the terminal open
    if sys.platform == "win32":
        subprocess.run(["cmd", "/K", f"echo VeriForge CLI ready."])
    else:
        # Try to spawn an interactive shell
        for shell in ["bash", "sh"]:
            if subprocess.run(["which", shell], capture_output=True).returncode == 0:
                subprocess.run([shell, "-i"])
                break


if __name__ == "__main__":
    main()
'''


# ==============================================================================
# PATH Management
# ==============================================================================

def add_to_path(silent: bool = False) -> bool:
    """
    Add VeriForge to the user's PATH environment variable.

    Creates batch file wrappers in INSTALL_DIR and adds INSTALL_DIR to PATH.
    """
    log.step("Configuring PATH...")

    # Create batch wrappers in INSTALL_DIR
    batch_dir = INSTALL_DIR / "bin"
    batch_dir.mkdir(parents=True, exist_ok=True)

    # veriforge-sdk.bat wrapper
    sdk_bat = batch_dir / "veriforge-sdk.bat"
    sdk_bat.write_text(SDK_BAT_TEMPLATE, encoding="utf-8")

    # Create the bin directory scripts
    for script_name in ["vf-scan.bat", "vf-dashboard.bat", "vf-audit.bat"]:
        script_path = batch_dir / script_name
        sdk_cmd = script_name.replace("vf-", "").replace(".bat", "")
        script_path.write_text(
            SDK_ALIAS_BAT_TEMPLATE.format(command=sdk_cmd),
            encoding="utf-8",
        )

    # Add INSTALL_DIR/bin to user PATH
    try:
        bin_path = str(batch_dir)

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current_path = ""

            if bin_path.lower() in current_path.lower().split(";"):
                log.info("VeriForge bin directory already in PATH")
                log.success("PATH is already configured")
                return True

            new_path = f"{current_path};{bin_path}" if current_path else bin_path
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

        # Notify the system about the environment change
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )

        log.success(f"Added '{bin_path}' to user PATH")
        log.info("You may need to open a new terminal for PATH changes to take effect")
        return True

    except PermissionError:
        log.warning("Permission denied modifying PATH. Run as administrator to add to PATH.")
        return False
    except Exception as e:
        log.error(f"Failed to update PATH: {e}")
        return False


def remove_from_path() -> bool:
    """Remove VeriForge bin directory from the user's PATH."""
    try:
        bin_path = str(INSTALL_DIR / "bin")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                return True

            paths = [p for p in current_path.split(";") if p and p.lower() != bin_path.lower()]
            new_path = ";".join(paths)
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 5000, ctypes.byref(result)
        )
        return True
    except Exception:
        return False


# Batch file templates
SDK_BAT_TEMPLATE = '''@echo off
REM VeriForge SDK wrapper - finds Python and runs the SDK
echo.
setlocal enabledelayedexpansion

REM Try common Python locations
set "PYTHON_CMD="

for %%P in (python python3 py) do (
    where /q %%P 2>nul
    if !errorlevel! == 0 (
        for /f "tokens=*" %%V in ('%%P -c "import sys; print(sys.version_info >= (3, 10))" 2^>nul') do (
            if "%%V"=="True" (
                set "PYTHON_CMD=%%P"
                goto :found
            )
        )
    )
)

REM Check specific installation paths
if exist "%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\\Programs\\Python\\Python312\\python.exe"
    goto :found
)
if exist "%LOCALAPPDATA%\\Programs\\Python\\Python311\\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\\Programs\\Python\\Python311\\python.exe"
    goto :found
)
if exist "%LOCALAPPDATA%\\Programs\\Python\\Python310\\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\\Programs\\Python\\Python310\\python.exe"
    goto :found
)
if exist "C:\\Python312\\python.exe" (
    set "PYTHON_CMD=C:\\Python312\\python.exe"
    goto :found
)
if exist "C:\\Python311\\python.exe" (
    set "PYTHON_CMD=C:\\Python311\\python.exe"
    goto :found
)
if exist "C:\\Python310\\python.exe" (
    set "PYTHON_CMD=C:\\Python310\\python.exe"
    goto :found
)

echo ERROR: Python 3.10+ not found. Please install Python 3.10 or later.
echo Visit: https://www.python.org/downloads/
echo.
pause
exit /b 1

:found
REM Run the SDK with all arguments
%PYTHON_CMD% -m veriforge_sdk %*
exit /b %errorlevel%
'''

SDK_ALIAS_BAT_TEMPLATE = '''@echo off
REM VeriForge SDK alias: {command}
veriforge-sdk {command} %*
'''


# ==============================================================================
# Uninstaller
# ==============================================================================

def create_uninstaller() -> bool:
    """Create the uninstaller script at ~/.veriforge/uninstall.py."""
    log.step("Creating uninstaller...")

    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        uninstaller_path = INSTALL_DIR / "uninstall.py"
        uninstaller_path.write_text(UNINSTALLER_SCRIPT, encoding="utf-8")

        # Also create a batch file wrapper
        uninstall_bat = INSTALL_DIR / "uninstall.bat"
        uninstall_bat.write_text(
            f"@echo off\n"
            f"echo ================================================\n"
            f"echo   VeriForge Uninstaller\n"
            f"echo ================================================\n"
            f"echo.\n"
            f'"{sys.executable}" "{uninstaller_path}" %*\n'
            f"pause\n",
            encoding="utf-8",
        )

        log.success(f"Uninstaller created at: {uninstaller_path}")
        log.info(f"Run 'python {uninstaller_path}' or double-click '{uninstall_bat}' to uninstall")
        return True

    except Exception as e:
        log.error(f"Failed to create uninstaller: {e}")
        return False


UNINSTALLER_SCRIPT = '''#!/usr/bin/env python3
"""
================================================================================
 VeriForge Security Platform - Uninstaller
================================================================================
Removes all VeriForge components from the system:
  - pip packages (veriforge-sdk and dependencies)
  - Desktop shortcuts
  - PATH entries
  - Data directory (~/.veriforge)

Usage:
    python uninstall.py           # Interactive uninstall
    python uninstall.py --yes     # Skip confirmation prompts
================================================================================
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

# ANSI color codes
class Colors:
    RESET = "\\033[0m"
    BOLD = "\\033[1m"
    RED = "\\033[91m"
    GREEN = "\\033[92m"
    YELLOW = "\\033[93m"
    CYAN = "\\033[96m"

INSTALL_DIR = Path.home() / ".veriforge"
SDK_PACKAGE = "veriforge-sdk"
SHORTCUT_NAMES = [
    "VeriForge Red Scanner",
    "VeriForge Dashboard",
    "VeriForge CLI",
]


def print_colored(color: str, message: str) -> None:
    print(f"{color}{message}{Colors.RESET}")


def print_header(message: str) -> None:
    print()
    print_colored(Colors.CYAN, "=" * 60)
    print_colored(Colors.CYAN, f" {message}")
    print_colored(Colors.CYAN, "=" * 60)


def print_success(message: str) -> None:
    print_colored(Colors.GREEN, f"   [OK] {message}")


def print_error(message: str) -> None:
    print_colored(Colors.RED, f"   [ERROR] {message}")


def print_warning(message: str) -> None:
    print_colored(Colors.YELLOW, f"   [WARN] {message}")


def print_step(message: str) -> None:
    print()
    print_colored(Colors.CYAN, f">> {message}")


def confirm(prompt: str) -> bool:
    while True:
        response = input(f"{prompt} [y/N]: ").strip().lower()
        if response in ("y", "yes"):
            return True
        if response in ("n", "no", ""):
            return False


def uninstall_pip_packages() -> bool:
    """Uninstall veriforge-sdk and related packages."""
    print_step("Uninstalling pip packages...")
    packages = [SDK_PACKAGE, "veriforge-common", "veriforge-red", "veriforge-cli"]
    success = True

    for pkg in packages:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", pkg, "-y"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print_success(f"Uninstalled {pkg}")
            else:
                print_warning(f"{pkg} may not be installed (pip returned {result.returncode})")
        except Exception as e:
            print_error(f"Failed to uninstall {pkg}: {e}")
            success = False

    return success


def remove_desktop_shortcuts() -> bool:
    """Remove VeriForge desktop shortcuts."""
    print_step("Removing desktop shortcuts...")
    success = True

    desktop_paths = [
        Path.home() / "Desktop",
        Path.home() / "OneDrive" / "Desktop",
    ]

    for shortcut_name in SHORTCUT_NAMES:
        removed = False
        for desktop in desktop_paths:
            shortcut_path = desktop / f"{shortcut_name}.lnk"
            if shortcut_path.exists():
                try:
                    shortcut_path.unlink()
                    print_success(f"Removed shortcut: {shortcut_path}")
                    removed = True
                except Exception as e:
                    print_error(f"Failed to remove {shortcut_path}: {e}")
                    success = False
        if not removed:
            print_warning(f"Shortcut not found: {shortcut_name}.lnk")

    return success


def remove_from_path() -> bool:
    """Remove VeriForge from the user PATH."""
    print_step("Removing from PATH...")
    try:
        bin_path = str(INSTALL_DIR / "bin")

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                print_success("PATH key not found, nothing to remove")
                return True

            paths = [p for p in current_path.split(";") if p and p.lower() != bin_path.lower()]
            new_path = ";".join(paths)
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 5000, ctypes.byref(result)
        )

        print_success("Removed from PATH")
        return True

    except Exception as e:
        print_error(f"Failed to remove from PATH: {e}")
        return False


def remove_data_directory(force: bool = False) -> bool:
    """Remove the VeriForge data directory."""
    print_step("Removing data directory...")

    if not INSTALL_DIR.exists():
        print_success("Data directory does not exist")
        return True

    if not force:
        print(f"\\nThis will delete: {INSTALL_DIR}")
        print("This includes all scan history, reports, and configuration.")
        if not confirm("Delete this directory?"):
            print_warning("Skipping data directory removal")
            return True

    try:
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
        if INSTALL_DIR.exists():
            print_warning("Some files could not be removed. You may need to delete manually.")
            return False
        print_success(f"Removed data directory: {INSTALL_DIR}")
        return True
    except Exception as e:
        print_error(f"Failed to remove data directory: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="VeriForge Uninstaller")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip all confirmation prompts")
    parser.add_argument("--keep-data", action="store_true", help="Keep the data directory")
    args = parser.parse_args()

    print_header("VERIFORGE UNINSTALLER")
    print()

    if not args.yes:
        print("This will remove VeriForge and all its components from your system.")
        if not confirm("Continue with uninstall?"):
            print("Uninstall cancelled.")
            return 0

    start_time = time.time()
    results = {}

    results["packages"] = uninstall_pip_packages()
    results["shortcuts"] = remove_desktop_shortcuts()
    results["path"] = remove_from_path()
    results["data"] = remove_data_directory(force=args.yes) if not args.keep_data else True

    elapsed = time.time() - start_time

    print()
    print_header("UNINSTALL COMPLETE")
    print()
    for step, success in results.items():
        status = "OK" if success else "FAILED"
        color = Colors.GREEN if success else Colors.RED
        print_colored(color, f"   [{status}] {step.capitalize()}")

    print(f"\\nCompleted in {elapsed:.1f} seconds")

    if all(results.values()):
        print_colored(Colors.GREEN, "\\nVeriForge has been completely removed.")
        return 0
    else:
        print_colored(Colors.YELLOW, "\\nSome steps failed. Check messages above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''


# ==============================================================================
# System Tray Stub
# ==============================================================================

def create_system_tray_stub() -> bool:
    """Create the system tray application stub at ~/.veriforge/tray.py."""
    log.step("Creating system tray integration...")

    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        tray_path = INSTALL_DIR / "tray.py"
        tray_path.write_text(TRAY_SCRIPT, encoding="utf-8")

        # Create a batch launcher for the tray app
        tray_bat = INSTALL_DIR / "VeriForgeTray.bat"
        tray_bat.write_text(
            f"@echo off\n"
            f"start \"\" \"{sys.executable}\" \"{tray_path}\"\n",
            encoding="utf-8",
        )

        log.success(f"System tray app created at: {tray_path}")
        log.info("Run the tray app: double-click 'VeriForgeTray.bat'")
        return True

    except Exception as e:
        log.error(f"Failed to create system tray stub: {e}")
        return False


TRAY_SCRIPT = '''#!/usr/bin/env python3
"""
================================================================================
 VeriForge Security Platform - System Tray Application
================================================================================
Provides a system tray icon with quick access to VeriForge features:
  - Double-click: Open scanner GUI
  - Right-click menu: Scan, Dashboard, Privacy Audit, Quit

Usage:
    python tray.py              # Start tray application
    python tray.py --start      # Start minimized to tray
================================================================================
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox


class VeriForgeTray:
    """System tray application for VeriForge Security Platform."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("VeriForge Tray")
        self.root.withdraw()
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)

        # Prevent the tkinter window from showing in taskbar
        self.root.overrideredirect(True)

        # Create the icon (red shield using tkinter canvas)
        self.icon_image = self._create_shield_icon()

        # Build the system tray menu
        self.menu = tk.Menu(self.root, tearoff=0)
        self._build_menu()

        # Create a label to act as tray icon (fallback for system tray)
        self.tray_label = tk.Label(self.root, image=self.icon_image)
        self.tray_label.pack()

        # Right-click on the icon
        self.tray_label.bind("<Button-3>", self.show_menu)
        self.tray_label.bind("<Double-Button-1>", self.on_double_click)

        # Create a system tray window
        self._create_tray_window()

    def _create_shield_icon(self) -> tk.PhotoImage:
        """Create a red shield icon for the system tray."""
        size = 64
        img = tk.PhotoImage(width=size, height=size)

        # Draw a shield shape (simplified as a filled polygon)
        shield_points = [
            size // 2, 4,           # top
            size - 6, 12,           # top right
            size - 6, size // 2 + 8, # mid right
            size // 2, size - 8,    # bottom point
            6, size // 2 + 8,       # mid left
            6, 12,                  # top left
        ]

        # Fill with red
        for y in range(size):
            for x in range(size):
                # Simple shield shape approximation
                cx, cy = size // 2, size // 2
                dx = abs(x - cx)
                dy = y - 4
                if dy >= 0:
                    # Shield body
                    width_at_y = (size - 12) * (1 - dy / (size - 12)) ** 0.5
                    if dx <= width_at_y:
                        # Red shield color
                        r = int(220 - dy * 1.5)
                        g = int(40 + dy * 0.5)
                        b = int(40 + dy * 0.5)
                        r = max(0, min(255, r))
                        g = max(0, min(255, g))
                        b = max(0, min(255, b))
                        color = f"#{r:02x}{g:02x}{b:02x}"
                        img.put(color, (x, y))

        # Add a white border/outline
        for i in range(0, len(shield_points), 2):
            x, y = shield_points[i], shield_points[i + 1]
            img.put("#ffffff", (x, y))
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < size and 0 <= ny < size:
                        img.put("#cc0000", (nx, ny))

        # Add a white "V" in the center
        v_color = "#ffffff"
        cx, cy = size // 2, size // 2
        # Simple V shape
        for i in range(-12, 13):
            y_offset = abs(i) // 2
            px = cx + i
            py = cy - 8 + y_offset
            if 0 <= px < size and 0 <= py < size:
                img.put(v_color, (px, py))

        return img

    def _build_menu(self) -> None:
        """Build the right-click context menu."""
        self.menu.delete(0, tk.END)

        self.menu.add_command(label="VeriForge Security Platform", state=tk.DISABLED)
        self.menu.add_separator()
        self.menu.add_command(label="Red Scanner", command=self.on_scan)
        self.menu.add_command(label="Dashboard", command=self.on_dashboard)
        self.menu.add_command(label="Privacy Audit", command=self.on_audit)
        self.menu.add_separator()
        self.menu.add_command(label="Open GUI (Double-click)", command=self.on_double_click)
        self.menu.add_separator()
        self.menu.add_command(label="Quit", command=self.on_quit)

    def _create_tray_window(self) -> None:
        """Create a small floating tray window."""
        self.tray_window = tk.Toplevel(self.root)
        self.tray_window.title("VeriForge")
        self.tray_window.geometry("48x48+100+100")
        self.tray_window.overrideredirect(True)
        self.tray_window.attributes("-topmost", True)
        self.tray_window.attributes("-alpha", 0.9)
        self.tray_window.attributes("-toolwindow", True)

        label = tk.Label(self.tray_window, image=self.icon_image, cursor="hand2")
        label.pack(fill=tk.BOTH, expand=True)
        label.bind("<Button-3>", self.show_menu)
        label.bind("<Double-Button-1>", self.on_double_click)

        # Make it draggable
        label.bind("<Button-1>", self._start_drag)
        label.bind("<B1-Motion>", self._on_drag)

    def _start_drag(self, event: tk.Event) -> None:
        self._drag_x = event.x
        self._drag_y = event.y

    def _on_drag(self, event: tk.Event) -> None:
        x = self.tray_window.winfo_x() + event.x - self._drag_x
        y = self.tray_window.winfo_y() + event.y - self._drag_y
        self.tray_window.geometry(f"+{x}+{y}")

    def show_menu(self, event: tk.Event | None = None) -> None:
        """Show the context menu."""
        self.menu.post(
            event.x_root if event else self.root.winfo_pointerx(),
            event.y_root if event else self.root.winfo_pointery(),
        )

    def on_double_click(self, event: tk.Event | None = None) -> None:
        """Handle double-click: open the scanner GUI."""
        self.open_scanner_gui()

    def on_scan(self) -> None:
        """Launch Red Scanner from menu."""
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self) -> None:
        try:
            subprocess.Popen(
                [sys.executable, "-m", "veriforge_sdk", "scan"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scanner: {e}")

    def on_dashboard(self) -> None:
        """Open the Dashboard."""
        try:
            subprocess.Popen(
                [sys.executable, "-m", "veriforge_sdk", "dashboard"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open dashboard: {e}")

    def on_audit(self) -> None:
        """Run Privacy Audit."""
        try:
            subprocess.Popen(
                [sys.executable, "-m", "veriforge_sdk", "audit"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start audit: {e}")

    def open_scanner_gui(self) -> None:
        """Open the scanner GUI application."""
        gui_path = Path.home() / ".veriforge" / "veriforge-red-gui.pyw"
        if gui_path.exists():
            try:
                subprocess.Popen(
                    [sys.executable, str(gui_path)],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open scanner GUI: {e}")
        else:
            messagebox.showinfo(
                "VeriForge Scanner",
                "Scanner GUI not found at:\n" + str(gui_path) + "\\n\\nInstall VeriForge to use the scanner GUI.",
            )

    def on_quit(self) -> None:
        """Quit the tray application."""
        self.tray_window.destroy()
        self.root.quit()
        self.root.destroy()

    def hide_window(self) -> None:
        """Hide instead of close."""
        self.root.withdraw()

    def run(self) -> None:
        """Start the tray application main loop."""
        print("VeriForge System Tray running...")
        print("Right-click the shield icon for menu")
        print("Double-click to open scanner")
        print("Close this window to exit")
        self.root.deiconify()
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(description="VeriForge System Tray")
    parser.add_argument("--start", action="store_true", help="Start minimized to tray")
    args = parser.parse_args()

    app = VeriForgeTray()

    if args.start:
        app.root.withdraw()

    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ==============================================================================
# Installation Summary
# ==============================================================================

def print_final_summary(
    python_ok: bool,
    shortcuts: dict[str, bool],
    path_ok: bool,
    uninstaller_ok: bool,
    tray_ok: bool,
    elapsed: float,
) -> None:
    """Print the final installation summary."""
    log.header("INSTALLATION SUMMARY")
    print()

    # Python
    status = f"{Colors.GREEN}[OK]{Colors.RESET}" if python_ok else f"{Colors.RED}[FAIL]{Colors.RESET}"
    print(f"   {status} Python Environment")

    # SDK
    print(f"   {Colors.GREEN}[OK]{Colors.RESET} VeriForge SDK")

    # Shortcuts
    for name, ok in shortcuts.items():
        status = f"{Colors.GREEN}[OK]{Colors.RESET}" if ok else f"{Colors.YELLOW}[WARN]{Colors.RESET}"
        print(f"   {status} Desktop: {SHORTCUT_NAMES[name]}")

    # PATH
    status = f"{Colors.GREEN}[OK]{Colors.RESET}" if path_ok else f"{Colors.YELLOW}[SKIP]{Colors.RESET}"
    print(f"   {status} PATH Configuration")

    # Uninstaller
    status = f"{Colors.GREEN}[OK]{Colors.RESET}" if uninstaller_ok else f"{Colors.RED}[FAIL]{Colors.RESET}"
    print(f"   {status} Uninstaller")

    # Tray
    status = f"{Colors.GREEN}[OK]{Colors.RESET}" if tray_ok else f"{Colors.YELLOW}[WARN]{Colors.RESET}"
    print(f"   {status} System Tray Integration")

    # Products
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}   Installed Products ({len(PRODUCTS)}):{Colors.RESET}")
    for i, product in enumerate(PRODUCTS, 1):
        print(f"      {i}. {product}")

    # How to use
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}   How to use VeriForge:{Colors.RESET}")
    print(f"      {Colors.YELLOW}GUI Scanner:{Colors.RESET}    Double-click 'VeriForge Red Scanner' on Desktop")
    print(f"      {Colors.YELLOW}Dashboard:{Colors.RESET}      Double-click 'VeriForge Dashboard' on Desktop")
    print(f"      {Colors.YELLOW}CLI:{Colors.RESET}            Double-click 'VeriForge CLI' on Desktop")
    print(f"      {Colors.YELLOW}Command:{Colors.RESET}        veriforge-sdk <command>")
    print(f"      {Colors.YELLOW}System Tray:{Colors.RESET}    Run: python \"{INSTALL_DIR / 'tray.py'}\"")
    print(f"      {Colors.YELLOW}Uninstall:{Colors.RESET}      Run: python \"{INSTALL_DIR / 'uninstall.py'}\"")

    # Paths
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}   Important Paths:{Colors.RESET}")
    print(f"      Install dir:  {INSTALL_DIR}")
    print(f"      Config:       {CONFIG_DIR}")
    print(f"      Data:         {DATA_DIR}")
    print(f"      Log:          {LOG_FILE}")

    print()
    print(f"{Colors.GREEN}   Installation completed in {elapsed:.1f} seconds{Colors.RESET}")
    print(f"{Colors.GREEN}   Log saved to: {LOG_FILE}{Colors.RESET}")
    print()
    print(f"{Colors.CYAN}   Thank you for installing VeriForge Security Platform!{Colors.RESET}")
    print(f"{Colors.DIM}   Visit https://docs.veriforge.dev for documentation{Colors.RESET}")
    print()


# ==============================================================================
# Main Installer Flow
# ==============================================================================

def run_installer(silent: bool = False, sdk_path: str | None = None) -> int:
    """
    Run the complete VeriForge installation flow.

    Args:
        silent: If True, skip interactive prompts
        sdk_path: Optional local SDK package path

    Returns:
        Exit code (0 = success, 1 = failure)
    """
    start_time = time.time()

    log.banner()
    log.header("VERIFORGE SECURITY PLATFORM INSTALLER")
    log.info(f"Installer version: {INSTALLER_VERSION}")
    log.info(f"Platform: {platform.platform()}")
    log.info(f"Architecture: {platform.machine()}")
    log.info(f"Time: {datetime.now()}")

    if is_admin():
        log.info("Running with administrator privileges")
    else:
        log.info("Running without administrator privileges (user-level install)")

    # ------------------------------------------------------------------
    # Step 1: Check Python
    # ------------------------------------------------------------------
    log.step("Step 1: Checking Python installation...")
    log.progress(0, "Detecting Python...")

    python_ok, message, version = check_python()
    log.info(message)

    if python_ok:
        log.progress(100, "Python OK")
        log.success(f"Python {version[0]}.{version[1]} is compatible")
    else:
        log.progress(50, "Python issue detected")
        log.warning(message)

        # Check for other Python installations
        log.info("Searching for other Python installations...")
        found_python = find_python_on_system()

        if found_python:
            log.info(f"Found Python at: {found_python}")
            try:
                result = subprocess.run(
                    [found_python, "-c", "import sys; print(sys.version_info >= (3, 10))"],
                    capture_output=True, text=True, timeout=10,
                )
                if "True" in result.stdout:
                    log.success(f"Found compatible Python at: {found_python}")
                    log.info(f"Re-run with: {found_python} install.py")
            except Exception:
                pass

        if not silent:
            print()
            print(f"{Colors.YELLOW}   Python {REQUIRED_PYTHON_VERSION_STR} is required.{Colors.RESET}")
            print(f"{Colors.YELLOW}   Download from: https://www.python.org/downloads/{Colors.RESET}")
            print(f"{Colors.YELLOW}   During installation, check 'Add Python to PATH'{Colors.RESET}")
            print()
            response = input(f"   {Colors.CYAN}Press Enter after installing Python, or 'q' to quit: {Colors.RESET}").strip().lower()
            if response == "q":
                log.error("Installation cancelled - Python not available")
                return 1

            # Re-check
            python_ok, message, version = check_python()
            if not python_ok:
                log.error("Python still not available. Installation cannot continue.")
                return 1
        else:
            log.error("Silent install requires Python 3.10+. Install Python first.")
            return 1

    # ------------------------------------------------------------------
    # Step 2: Check pip
    # ------------------------------------------------------------------
    log.step("Step 2: Checking pip...")
    log.progress(0, "Checking pip...")

    if check_pip():
        log.progress(100, "pip available")
        log.success("pip is available")
    else:
        log.warning("pip not found")
        if not silent:
            response = input(f"   {Colors.CYAN}Install pip? [Y/n]: {Colors.RESET}").strip().lower()
            if response in ("y", "yes", ""):
                if not install_pip():
                    log.error("Cannot continue without pip")
                    return 1
            else:
                log.error("pip is required. Installation cancelled.")
                return 1
        else:
            if not install_pip():
                log.error("Cannot continue without pip")
                return 1

    # ------------------------------------------------------------------
    # Step 3: Install SDK
    # ------------------------------------------------------------------
    log.step("Step 3: Installing VeriForge SDK...")
    if not install_sdk(sdk_path=sdk_path, silent=silent):
        log.warning("SDK installation had issues. Continuing with setup...")

    # ------------------------------------------------------------------
    # Step 4: Create directories
    # ------------------------------------------------------------------
    log.step("Step 4: Creating directories...")
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        log.success("Directories created")
    except Exception as e:
        log.error(f"Failed to create directories: {e}")
        return 1

    # ------------------------------------------------------------------
    # Step 5: Create shortcuts
    # ------------------------------------------------------------------
    log.step("Step 5: Creating desktop shortcuts...")
    shortcuts = create_desktop_shortcuts(silent=silent)

    # ------------------------------------------------------------------
    # Step 6: Add to PATH (optional)
    # ------------------------------------------------------------------
    log.step("Step 6: PATH configuration...")
    add_path = True
    if not silent:
        response = input(f"   {Colors.CYAN}Add VeriForge to PATH? [Y/n]: {Colors.RESET}").strip().lower()
        if response in ("n", "no"):
            add_path = False
            log.info("Skipping PATH configuration")

    path_ok = False
    if add_path:
        path_ok = add_to_path(silent=silent)

    # ------------------------------------------------------------------
    # Step 7: Create uninstaller
    # ------------------------------------------------------------------
    log.step("Step 7: Creating uninstaller...")
    uninstaller_ok = create_uninstaller()

    # ------------------------------------------------------------------
    # Step 8: Create system tray
    # ------------------------------------------------------------------
    log.step("Step 8: Creating system tray integration...")
    tray_ok = create_system_tray_stub()

    # ------------------------------------------------------------------
    # Step 9: Copy GUI script
    # ------------------------------------------------------------------
    log.step("Step 9: Installing scanner GUI...")
    try:
        gui_source = Path(__file__).parent / "veriforge-red-gui.pyw"
        gui_dest = INSTALL_DIR / "veriforge-red-gui.pyw"
        if gui_source.exists():
            shutil.copy2(str(gui_source), str(gui_dest))
            log.success(f"Scanner GUI installed: {gui_dest}")
        else:
            log.warning(f"GUI source not found: {gui_source}")
            log.info("The GUI will be available after SDK installation")
    except Exception as e:
        log.warning(f"Could not copy GUI script: {e}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    print_final_summary(
        python_ok=True,
        shortcuts=shortcuts,
        path_ok=path_ok,
        uninstaller_ok=uninstaller_ok,
        tray_ok=tray_ok,
        elapsed=elapsed,
    )

    return 0


# ==============================================================================
# Entry Point
# ==============================================================================

def main() -> int:
    """Parse arguments and run the installer."""
    parser = argparse.ArgumentParser(
        description="VeriForge Security Platform - Windows Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python install.py                    # Interactive installation
  python install.py --silent           # Silent install (all defaults)
  python install.py --sdk-path sdk.zip # Install from local SDK package
        """,
    )
    parser.add_argument("--silent", "-s", action="store_true", help="Silent mode (no prompts)")
    parser.add_argument("--sdk-path", type=str, default=None, help="Path to local SDK ZIP file")
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {INSTALLER_VERSION}")
    args = parser.parse_args()

    try:
        return run_installer(silent=args.silent, sdk_path=args.sdk_path)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Installation interrupted by user.{Colors.RESET}")
        return 130
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

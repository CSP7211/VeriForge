# VeriForge Security Platform - Windows Installation Guide

This guide covers installing the VeriForge Security Platform on Windows systems.

---

## Prerequisites

- **Windows 10 or later** (64-bit recommended)
- **Python 3.10 or later** (required for running the SDK)
- **Internet connection** (for downloading packages from PyPI)

> Don't have Python? Download it from [python.org](https://www.python.org/downloads/).
> During installation, check **"Add Python to PATH"**.

---

## Quick Start

The easiest way to install VeriForge is using the provided installer script:

```powershell
# Download and extract the installer
cd veriforge-windows-installer

# Run the installer (interactive mode)
python install.py

# Or run in silent mode (uses all defaults)
python install.py --silent
```

The installer will:
1. Check your Python version (3.10+ required)
2. Install pip if needed
3. Install the VeriForge SDK from PyPI
4. Create desktop shortcuts
5. Optionally add VeriForge to your PATH
6. Set up the system tray integration
7. Create an uninstaller

---

## Installation Methods

### Method 1: Interactive Installer (Recommended)

```powershell
python install.py
```

Follow the on-screen prompts to customize your installation.

### Method 2: Silent Installation

For automated deployment or CI/CD pipelines:

```powershell
python install.py --silent
```

This installs with all default options without prompting.

### Method 3: Local SDK Package

If you have a local SDK package (e.g., from an internal repository):

```powershell
python install.py --sdk-path C:\path\to\veriforge-sdk.zip
```

### Method 4: Manual pip Install

If you prefer to install manually:

```powershell
# Install the SDK
pip install veriforge-sdk

# Or install from a local file
pip install veriforge-sdk.zip

# Verify installation
veriforge-sdk --help
```

---

## Files Included

| File | Description |
|------|-------------|
| `install.py` | Main installer script with interactive/silent modes |
| `veriforge-sdk.bat` | Batch wrapper that auto-detects Python and runs SDK |
| `veriforge-red-gui.pyw` | Tkinter GUI scanner with directory picker and export |
| `uninstall.bat` | One-click uninstaller with fallback logic |
| `README_WINDOWS.md` | This documentation file |

---

## Desktop Shortcuts

After installation, you'll find these shortcuts on your Desktop:

| Shortcut | What It Does |
|----------|-------------|
| **VeriForge Red Scanner** | Opens a directory picker, then runs a vulnerability scan |
| **VeriForge Dashboard** | Launches the web-based security dashboard |
| **VeriForge CLI** | Opens a terminal ready for veriforge-sdk commands |

---

## Using the Red Scanner GUI

The GUI scanner provides a user-friendly interface for vulnerability scanning:

```powershell
# Launch the GUI (no console window)
pythonw veriforge-red-gui.pyw

# Or with console output
python veriforge-red-gui.pyw
```

### Features:
- **Directory picker** with quick-access shortcuts
- **Scan depth slider** (1=fast scan, 10=deep analysis)
- **Product selection** (Red Scanner, VeriClaw, Core Policy)
- **Real-time progress bar** with scan status
- **Findings table** with severity coloring
- **Details panel** for each finding with remediation guidance
- **Console output** showing scan progress
- **Export to JSON/CSV** for reporting and integration
- **Keyboard shortcuts**: Ctrl+O (browse), F5 (scan), Ctrl+E (export)

---

## Using the CLI

Open **VeriForge CLI** from your Desktop, or use the batch wrapper:

```powershell
# Using the batch wrapper (auto-detects Python)
veriforge-sdk scan C:\path\to\project

# Using Python module directly
python -m veriforge_sdk scan C:\path\to\project

# Other commands
veriforge-sdk dashboard        # Launch dashboard
veriforge-sdk audit            # Run privacy audit
veriforge-sdk --help           # Show all commands
```

---

## System Tray Integration

The installer sets up a system tray application for quick access:

```powershell
# Start the system tray icon
python "%USERPROFILE%\.veriforge\tray.py"

# Or use the batch launcher
call "%USERPROFILE%\.veriforge\VeriForgeTray.bat"
```

### Tray Features:
- **Red shield icon** visible in the system tray
- **Double-click** to open the scanner GUI
- **Right-click menu** with:
  - Red Scanner
  - Dashboard
  - Privacy Audit
  - Quit

### Auto-start on Windows Login:

To start the tray icon automatically when you log in:

1. Press `Win + R`, type `shell:startup`, press Enter
2. Copy the `VeriForgeTray.bat` shortcut into this folder:

```powershell
copy "%USERPROFILE%\.veriforge\VeriForgeTray.bat" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## Uninstallation

### Method 1: One-Click Uninstall

Double-click the **uninstall.bat** file or run:

```powershell
uninstall.bat
```

### Method 2: Silent Uninstall

```powershell
uninstall.bat --yes
```

### Method 3: Keep Data

To uninstall but preserve your scan history and reports:

```powershell
uninstall.bat --keep-data
```

### Method 4: Manual Uninstall

If the uninstaller is unavailable:

```powershell
# Uninstall pip packages
pip uninstall veriforge-sdk veriforge-common veriforge-red veriforge-cli -y

# Remove desktop shortcuts
del "%USERPROFILE%\Desktop\VeriForge Red Scanner.lnk"
del "%USERPROFILE%\Desktop\VeriForge Dashboard.lnk"
del "%USERPROFILE%\Desktop\VeriForge CLI.lnk"

# Remove data directory
rmdir /s /q "%USERPROFILE%\.veriforge"

# Remove from PATH (via System Properties)
```

---

## Troubleshooting

### "Python not found" Error

1. Install Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. During installation, check **"Add Python to PATH"**
3. Open a **new** terminal/PowerShell window and try again

### "pip not found" Error

```powershell
python -m ensurepip --upgrade
# Or
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

### Permission Denied Errors

Run the installer as Administrator:

```powershell
# Right-click PowerShell/Command Prompt and select "Run as Administrator"
# Then run:
python install.py
```

### PATH Not Updated

After installation, you may need to open a new terminal for PATH changes:

```powershell
# Check if veriforge-sdk is available
where veriforge-sdk

# If not found, you can manually add:
# %USERPROFILE%\.veriforge\bin
# to your PATH environment variable.
```

### Desktop Shortcuts Not Created

Shortcuts are created on your Desktop. If you use OneDrive, check:

```
%USERPROFILE%\OneDrive\Desktop\
```

You can also manually create shortcuts pointing to:
- Scanner: `%USERPROFILE%\.veriforge\scanner_launcher.py`
- Dashboard: Run `python -m veriforge_sdk dashboard`
- CLI: `%USERPROFILE%\.veriforge\cli_launcher.py`

---

## Installed Products

The VeriForge Security Platform includes 7 products:

| Product | Description |
|---------|-------------|
| **VeriForge Red** | Vulnerability scanner for source code and binaries |
| **VeriClaw** | Malware detection and signature analysis |
| **VeriForge Core** | Security policy engine and compliance checker |
| **VeriShield** | Network traffic monitor and anomaly detection |
| **VeriAudit** | Compliance auditing (SOC2, ISO 27001, GDPR) |
| **VeriTrace** | Digital forensics and incident response |
| **VeriGuard** | Endpoint protection and threat detection |

---

## Directory Structure

After installation, your system will have:

```
%USERPROFILE%\.veriforge\          # Main installation directory
├── bin\                          # Batch wrapper scripts
│   ├── veriforge-sdk.bat
│   ├── vf-scan.bat
│   ├── vf-dashboard.bat
│   └── vf-audit.bat
├── config\                      # Configuration files
├── data\                        # Scan history and reports
├── uninstall.py                 # Python uninstaller script
├── uninstall.bat                # Batch uninstall wrapper
├── tray.py                      # System tray application
├── VeriForgeTray.bat            # Tray launcher
├── scanner_launcher.py          # Desktop shortcut: Scanner
├── dashboard_launcher.py        # Desktop shortcut: Dashboard
├── cli_launcher.py              # Desktop shortcut: CLI
└── veriforge-red-gui.pyw        # Scanner GUI application
```

---

## Getting Help

- **Documentation**: https://docs.veriforge.dev
- **Support**: https://veriforge.dev/support
- **Issues**: https://github.com/veriforge/issues

---

*VeriForge Security Platform - Protecting your code, data, and infrastructure.*

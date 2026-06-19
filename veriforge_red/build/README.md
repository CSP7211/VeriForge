# VeriForge Red - Build & Release Documentation

Complete build instructions for packaging VeriForge Red on all supported platforms.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Windows Build (.exe)](#windows-build)
- [Android Build (.apk)](#android-build)
- [Release Checklist](#release-checklist)
- [Code Signing](#code-signing)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### All Platforms

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.10+ | Core runtime |
| Git | 2.30+ | Version control |
| Make | 4.0+ | Build orchestration |

### Platform-Specific

**Windows:**
- Windows 10/11 (64-bit)
- PowerShell 5.1+ or Windows Terminal
- Visual C++ Redistributable 2015-2022

**Android:**
- Ubuntu 20.04+ or WSL2 (for Buildozer)
- Android SDK (API 26+)
- Java JDK 11+

---

## Windows Build

### 1. Setup Environment

```powershell
# Clone the repository
git clone https://github.com/veriforge/red.git
cd red

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install pyinstaller
```

### 2. Build Executable

```powershell
# Full build with all modules
pyinstaller --name VeriForgeRed `
  --onefile `
  --windowed `
  --icon=assets/icon.ico `
  --add-data "veriforge_red;veriforge_red" `
  --hidden-import=cryptography `
  --hidden-import=watchdog `
  main.py

# Service-only build (background daemon)
pyinstaller --name VeriForgeRed-Service `
  --onefile `
  --console `
  --icon=assets/icon.ico `
  service_main.py

# Portable build (directory, no installer)
pyinstaller --name VeriForgeRed `
  --onedir `
  --windowed `
  --icon=assets/icon.ico `
  main.py
```

### 3. Create Installer (Optional)

```powershell
# Using NSIS
makensis installer.nsi

# Or create portable zip
Compress-Archive -Path dist/VeriForgeRed -DestinationPath VeriForgeRed-Portable.zip
```

### 4. Verify Build

```powershell
# Check executable runs
.\dist\VeriForgeRed.exe --version

# Run smoke tests
.\dist\VeriForgeRed.exe scan --target tests/fixtures/clean_project
```

### Build Outputs

| File | Size (est.) | Description |
|------|-------------|-------------|
| `VeriForgeRed.exe` | ~45 MB | Main application (single file) |
| `VeriForgeRed-Service.exe` | ~38 MB | Background service daemon |
| `VeriForgeRed-Portable.zip` | ~42 MB | Portable directory build |

---

## Android Build

### 1. Setup Environment (Ubuntu/WSL)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv git zip unzip

# Install Buildozer and dependencies
pip3 install buildozer cython

# Install Android SDK dependencies
sudo apt install -y libncurses5-dev libffi-dev libssl-dev \
  automake autoconf libtool pkg-config zlib1g-dev
```

### 2. Initialize Buildozer

```bash
cd veriforge_red/android

# Generate buildozer.spec (first time only)
buildozer init

# Edit buildozer.spec key settings:
# title = VeriForge Red
# package.name = veriforgered
# package.domain = com.veriforge
# source.dir = .
# version = 1.0.0
# requirements = python3,kivy,cryptography,watchdog
# orientation = portrait
# icon.filename = assets/icon.png
```

### 3. Build APK

```bash
# Debug build
buildozer -v android debug

# Release build
buildozer -v android release

# Build with specific architecture
buildozer -v android debug --arch=arm64-v8a
```

### 4. Locate Output

```bash
# Debug APK
ls bin/VeriForgeRed-*-debug.apk

# Release APK (unsigned)
ls bin/VeriForgeRed-*-release-unsigned.apk
```

### Build Outputs

| File | Size (est.) | Description |
|------|-------------|-------------|
| `VeriForgeRed.apk` | ~25 MB | Production release |
| `VeriForgeRed-debug.apk` | ~28 MB | Debug build with logging |

---

## Release Checklist

Use this checklist before publishing a new release.

### Pre-Build

- [ ] Version bumped in all relevant files:
  - `veriforge_red/__init__.py`
  - `veriforge_red/android/buildozer.spec`
  - `veriforge_red/website/index.html` (version strings)
  - `veriforge_red/website/download.html` (version strings)
- [ ] `CHANGELOG.md` updated with release notes
- [ ] All tests passing: `pytest -v`
- [ ] Security scan clean: `veriforge-red scan --target .`
- [ ] Git tag created: `git tag -a v1.0.0 -m "Release v1.0.0"`

### Build

- [ ] Windows `.exe` built and tested
- [ ] Windows Service `.exe` built
- [ ] Windows Portable `.zip` created
- [ ] Android `.apk` built and tested on device
- [ ] Android debug `.apk` built

### Verification

- [ ] SHA-256 checksums computed for all files
- [ ] Checksums added to download page
- [ ] Files scanned with antivirus (false positive check)
- [ ] Tested on clean Windows 10 VM
- [ ] Tested on clean Windows 11 VM
- [ ] Tested on Android 10, 12, 14
- [ ] No network calls detected (Wireshark/pcap)

### Distribution

- [ ] GitHub Release created with:
  - [ ] Release notes from CHANGELOG
  - [ ] All build artifacts attached
  - [ ] SHA-256 checksums in release notes
- [ ] Website download page updated with new checksums
- [ ] Website version badges updated
- [ ] Social announcement drafted

---

## Code Signing

### Windows (Code Signing Certificate)

```powershell
# Sign with EV certificate (recommended)
signtool sign /f certificate.pfx /p $env:CERT_PASSWORD `
  /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
  dist\VeriForgeRed.exe

# Verify signature
signtool verify /pa dist\VeriForgeRed.exe
```

> **Note:** Obtain a code signing certificate from a trusted CA (DigiCert, Sectigo, etc.). EV certificates provide immediate SmartScreen reputation. Standard OV certificates build reputation over time.

### Android (App Signing)

```bash
# Generate keystore (one-time)
keytool -genkey -v -keystore veriforge-release.keystore \
  -alias veriforge -keyalg RSA -keysize 4096 -validity 10000

# Sign release APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
  -keystore veriforge-release.keystore \
  bin/VeriForgeRed-release-unsigned.apk veriforge

# Align with zipalign
zipalign -v 4 \
  bin/VeriForgeRed-release-unsigned.apk \
  bin/VeriForgeRed.apk

# Verify
apksigner verify bin/VeriForgeRed.apk
```

> **Store the keystore securely.** Losing the keystore means you cannot update the app on Google Play.

---

## Troubleshooting

### Windows Build Issues

| Issue | Solution |
|-------|----------|
| `MSVCP140.dll not found` | Install Visual C++ Redistributable 2015-2022 |
| `Access denied` during build | Run PowerShell as Administrator |
| Large file size | Use UPX compression: `--upx-dir /path/to/upx` |
| False positive antivirus | Submit to Microsoft for analysis: https://www.microsoft.com/en-us/wdsi/filesubmission |
| SmartScreen warning | Sign with EV certificate, or submit unsigned binary for reputation scan |

### Android Build Issues

| Issue | Solution |
|-------|----------|
| `SDK not found` | Run `buildozer android update` to download SDK |
| `Java version mismatch` | Ensure JDK 11+ is installed and `JAVA_HOME` is set |
| ARM64 build fails | Add `--arch=arm64-v8a` flag |
| App crashes on launch | Check `adb logcat` for Python/Kivy errors |
| Large APK size | Enable minification in buildozer.spec |

### General Issues

| Issue | Solution |
|-------|----------|
| Slow build times | Use SSD, enable ccache, use `--clean` sparingly |
| Missing modules | Add to `--hidden-import` (PyInstaller) or `requirements` (Buildozer) |
| Import errors at runtime | Check `Analysis.binaries` and `Analysis.datas` in spec file |

---

## Build Commands Summary

```bash
# Quick reference for all builds

# Windows - all variants
make build-windows        # Main .exe
make build-windows-service # Service .exe
make build-windows-portable # Portable .zip

# Android
make build-android        # Release APK
make build-android-debug  # Debug APK

# All platforms
make build-all            # Everything

# Release
make release VERSION=1.0.0 # Full release with tag and artifacts
```

---

## Contact

- **Issues:** https://github.com/veriforge/red/issues
- **Security:** security@veriforge.dev
- **Docs:** https://docs.veriforge.dev

---

*VeriForge Security &copy; 2026. MIT License.*

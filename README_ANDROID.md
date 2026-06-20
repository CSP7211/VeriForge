# VeriForge — Android Installation Guide

Complete guide to installing and running the VeriForge security platform on Android devices using Termux.

---

## Table of Contents

1. [Overview](#overview)
2. [Step 1: Install Termux](#step-1-install-termux)
3. [Step 2: Run the Installer](#step-2-run-the-installer)
4. [Step 3: Usage](#step-3-usage)
5. [Step 4: Build APK (Optional)](#step-4-build-apk-optional)
6. [Architecture](#architecture)
7. [Troubleshooting](#troubleshooting)
8. [Reference](#reference)

---

## Overview

VeriForge is a Python-based security platform. On Android, it runs inside **Termux** — a terminal emulator that provides a full Linux environment. This installer sets up:

| Component | Description |
|-----------|-------------|
| **VeriForge SDK** | Core security library with cryptographic tools |
| **VeriForge Red** | Security scanner engine |
| **Dashboard** | HTTP-based reporting dashboard |
| **Privacy Audit** | Privacy-sensitive data detection |

### Requirements

- **Android 7.0+** (API 24+ recommended)
- **Storage**: ~250 MB free space
- **Network**: Wi-Fi for downloading packages
- **RAM**: 2 GB minimum (4 GB recommended)

---

## Step 1: Install Termux

Termux must be installed from **F-Droid**, not the Google Play Store. The Play Store version is deprecated and no longer maintained.

### 1.1 Install F-Droid

1. Open your Android browser
2. Navigate to: <https://f-droid.org/>
3. Download and install the F-Droid APK
4. You may need to enable **"Install unknown apps"** for your browser

### 1.2 Install Termux from F-Droid

1. Open the F-Droid app
2. Search for **"Termux"**
3. Tap **Install**
4. Wait for installation to complete

### 1.3 Grant Storage Permission

Open Termux and run:

```bash
termux-setup-storage
```

Tap **Allow** when prompted for storage permission. This creates a `~/storage` symlink to your device's shared storage.

### 1.4 (Optional) Install Termux Add-ons

| Add-on | Purpose | Install Via |
|--------|---------|-------------|
| **Termux:Widget** | Home screen shortcuts | F-Droid |
| **Termux:Tasker** | Automation integration | F-Droid |
| **Termux:API** | Hardware/camera access | F-Droid |

```bash
# Install Termux:Widget from F-Droid, then create shortcuts folder
mkdir -p ~/.shortcuts
```

---

## Step 2: Run the Installer

### Quick Install (One-Liner)

Copy and paste this into Termux:

```bash
curl -fsSL https://raw.githubusercontent.com/CSP7211/VeriForge/main/install.sh | bash
```

### Manual Install (Recommended)

1. **Download the installer:**

```bash
cd ~
curl -O https://raw.githubusercontent.com/CSP7211/VeriForge/main/install.sh
# or if you have the installer locally:
# cp /sdcard/Download/install.sh ~/install.sh
```

2. **Make it executable:**

```bash
chmod +x install.sh
```

3. **Run the installer:**

```bash
bash install.sh
```

### Installer Options

```bash
bash install.sh --help        # Show help
bash install.sh --no-scan     # Skip verification scan
bash install.sh --sdk-only    # Install only the SDK (no scanner)
```

### What the Installer Does

```
┌─────────────────────────────────────────┐
│ 1. Check Termux environment             │
│ 2. Update Termux packages (pkg update)  │
│ 3. Install python, git, openssl         │
│ 4. Install pip packages                 │
│    - cryptography, jinja2               │
│ 5. Clone VeriForge from GitHub          │
│ 6. Install VeriForge SDK (pip -e)       │
│ 7. Install VeriForge Red (pip -e)       │
│ 8. Create launcher scripts              │
│    - veriforge-red                      │
│    - veriforge-dashboard                │
│    - veriforge-privacy                  │
│    - veriforge-sdk                      │
│ 9. Create Android shortcuts             │
│ 10. Verify installation                 │
│ 11. Show completion message             │
└─────────────────────────────────────────┘
```

The installer includes:
- **Colored output** with progress indicators
- **Retry logic** for network operations
- **Error handling** with detailed logging
- **Spinners** for long-running operations

Installation typically takes **5–15 minutes** depending on your connection speed.

---

## Step 3: Usage

After installation, the following commands are available in Termux:

### 3.1 Quick Security Scan

```bash
# Scan default path (/sdcard)
veriforge-red

# Scan specific directory
veriforge-red /sdcard/Download

# Quick scan (faster, less thorough)
veriforge-red /sdcard --quick

# Scan with verbose output
veriforge-red /sdcard -v
```

### 3.2 HTTP Dashboard

```bash
# Start dashboard on default port (8080)
veriforge-dashboard

# Start on custom port
veriforge-dashboard 8888

# Then open in browser:
# http://localhost:8080
```

### 3.3 Privacy Audit

```bash
# Audit default path
veriforge-privacy

# Audit specific directory
veriforge-privacy /sdcard

# Output JSON report
veriforge-privacy /sdcard --json
```

### 3.4 SDK CLI

```bash
# SDK help
veriforge-sdk --help

# List available modules
veriforge-sdk list

# Run SDK command
veriforge-sdk <command> [options]
```

### 3.5 Home Screen Shortcuts

If you installed **Termux:Widget**:

1. Long-press on your Android home screen
2. Tap **Widgets**
3. Find **Termux** in the list
4. Drag **"Termux Shortcut"** to your home screen
5. Select the **VeriForge-Scan** script

---

## Step 4: Build APK (Optional)

You can build a standalone Android APK with a native Kivy GUI.

### Prerequisites

1. **Linux or macOS** build machine (or Termux with proot-distro)
2. **Python 3.8+** on the build machine
3. **Buildozer** and **Cython**:

```bash
pip install buildozer cython
```

### Build Steps

1. **Clone the repository:**

```bash
git clone https://github.com/CSP7211/VeriForge.git
cd VeriForge/android
```

2. **Initialize buildozer** (first time only):

```bash
buildozer init
# Then edit buildozer.spec with the provided configuration
```

3. **Build debug APK:**

```bash
buildozer android debug
```

4. **Deploy to connected device:**

```bash
buildozer android debug deploy run
```

### Buildozer Configuration

Use the provided `buildozer.spec`:

```ini
[app]
title = VeriForgeRed
package.name = VeriForgeRed
package.domain = com.veriforge
source.dir = .
version = 1.0.0
requirements = python3,kivy==2.2.1,cryptography,jinja2,openssl,requests,pyjnius,android
orientation = portrait
services = VeriForgeScan:veriforge-service.py
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,FOREGROUND_SERVICE,WAKE_LOCK,POST_NOTIFICATIONS,FOREGROUND_SERVICE_DATA_SYNC,ACCESS_NETWORK_STATE
android.archs = arm64-v8a, armeabi-v7a
android.minapi = 21
fullscreen = 0
```

### Build Presets

```bash
# Quick debug build (single arch)
buildozer android debug @quick

# CI/automated build
buildozer android debug @ci

# Release build (AAB for Play Store)
buildozer android release @release
```

### Common Build Issues

| Issue | Solution |
|-------|----------|
| `ndk not found` | Run `buildozer android ndk` or set `android.ndk_path` |
| `java not found` | Install OpenJDK 17: `sudo apt install openjdk-17-jdk` |
| Build out of memory | Add `android.gradle_options = -Xmx2048m` to buildozer.spec |
| Recipe fails | Clean and rebuild: `buildozer android clean` |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Android OS Layer                   │
│  ┌──────────┐  ┌──────────────────────┐    │
│  │  GUI APK  │  │     Termux Shell     │    │
│  │ (Kivy UI) │  │  ┌────────────────┐  │    │
│  │           │  │  │ install.sh     │  │    │
│  │ • Scan    │  │  │                │  │    │
│  │ • Results │  │  │ veriforge-red ──┼──┼────┼──► $PREFIX/bin
│  │ • Status  │  │  │ veriforge-dash──┤  │    │
│  └─────┬─────┘  │  │ veriforge-priv──┤  │    │
│        │         │  │ veriforge-sdk───┤  │    │
│        │         │  └────────────────┘  │    │
│        │         └──────────────────────┘    │
│        │                                      │
│  ┌─────▼──────────────────────────────────┐  │
│  │      VeriForge Background Service       │  │
│  │   (PythonService + foreground notif)    │  │
│  └─────────────────────────────────────────┘  │
│                    │                          │
│  ┌─────────────────▼──────────────────────┐  │
│  │    /sdcard (Device Storage)            │  │
│  │    Files to scan: downloads, docs, etc │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

---

## Troubleshooting

### Installation Issues

#### "Not running inside Termux"

**Cause**: The `$PREFIX` environment variable is not set.

**Solution**: You must run the installer inside a Termux shell, not in ADB or another terminal.

```bash
# Verify you're in Termux
echo $PREFIX
# Should output: /data/data/com.termux/files/usr
```

---

#### "pkg update failed"

**Cause**: Network issues or outdated Termux packages.

**Solution**:

```bash
# Force repository update
pkg update -y --force-yes

# If that fails, reset repositories
termux-change-repo
# Select a different mirror (e.g., Grimler.se)
```

---

#### "Failed to install dependencies"

**Cause**: Disk space or network issues.

**Solution**:

```bash
# Check free space
df -h $HOME

# Clear package cache
pkg clean

# Retry with verbose output
pkg install python git openssl -y
```

---

#### "Git clone failed"

**Cause**: Network connectivity or GitHub availability.

**Solution**:

```bash
# Test connectivity
ping -c 3 github.com

# Use a mirror or download ZIP instead
curl -L -o veriforge.zip https://github.com/CSP7211/VeriForge/archive/refs/heads/main.zip
unzip veriforge.zip
mv VeriForge-main VeriForge
```

---

#### "pip install cryptography failed"

**Cause**: Missing build dependencies for the cryptography package.

**Solution**:

```bash
# Install additional build dependencies
pkg install rust cargo libffi openssl-tool -y

# Upgrade pip first
pip install --upgrade pip setuptools wheel

# Retry
pip install cryptography
```

---

### Runtime Issues

#### "Permission denied" when scanning

**Solution**:

```bash
# Grant storage permission
termux-setup-storage

# Check permission
ls ~/storage/shared/Download

# If still failing, try direct /sdcard access
ls /sdcard/Download
```

---

#### "command not found: veriforge-red"

**Solution**:

```bash
# Check if the launcher exists
ls $PREFIX/bin/veriforge-red

# If missing, re-run the installer
bash install.sh

# Or source your shell profile
source $PREFIX/etc/bash.bashrc
```

---

#### "Scan hangs or takes too long"

**Cause**: Large directories or deep recursion.

**Solution**:

```bash
# Use quick scan instead
veriforge-red /sdcard --quick

# Scan a smaller directory
veriforge-red /sdcard/Download

# Set a timeout
# (edit the launcher script to add --timeout)
```

---

#### "Dashboard not accessible from browser"

**Solution**:

```bash
# Bind to all interfaces
veriforge-dashboard 0.0.0.0:8080

# Then access via:
# http://localhost:8080    (on device)
# http://<device-ip>:8080  (from another device on same network)
```

---

### APK Build Issues

#### "Buildozer command not found"

```bash
pip install buildozer cython
```

---

#### "SDK/NDK download fails"

```bash
# Set proxy if behind firewall
export HTTP_PROXY=http://proxy:port
export HTTPS_PROXY=http://proxy:port

# Or manually download and set paths
# android.sdk_path = /path/to/android-sdk
# android.ndk_path = /path/to/android-ndk
```

---

#### "APK installs but crashes immediately"

**Common causes**:
1. Missing permissions — ensure `android.permissions` includes storage permissions
2. Architecture mismatch — ensure target arch matches device (`adb shell getprop ro.product.cpu.abi`)
3. Kivy version incompatibility — check `requirements` in buildozer.spec

**Debug steps**:

```bash
# View device logs
adb logcat | grep -i "veriforge\|python\|kivy"

# Rebuild with debug symbols
buildozer android debug
```

---

### Getting Help

If issues persist:

1. **Check the install log:**
   ```bash
   cat ~/veriforge_install.log
   ```

2. **Check the service log:**
   ```bash
   cat ~/veriforge_service.log
   ```

3. **Report issues:**
   - GitHub Issues: <https://github.com/CSP7211/VeriForge/issues>
   - Include the log file and Android version

---

## Reference

### File Locations

| File | Path |
|------|------|
| Installer | `~/install.sh` |
| Source code | `~/VeriForge/` |
| Launcher scripts | `$PREFIX/bin/veriforge-*` |
| Install log | `~/veriforge_install.log` |
| Service log | `~/veriforge_service.log` |
| Last scan results | `~/.veriforge_last_scan.json` |
| Shortcuts | `~/.shortcuts/` |

### Launcher Scripts

| Script | Purpose |
|--------|---------|
| `veriforge-red` | Security scanner |
| `veriforge-dashboard` | HTTP dashboard server |
| `veriforge-privacy` | Privacy audit tool |
| `veriforge-sdk` | SDK CLI interface |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `$PREFIX` | Termux root path |
| `$HOME` | User home directory |
| `$PATH` | Includes `$PREFIX/bin` |

### Uninstall

To remove VeriForge:

```bash
# Remove source code
rm -rf ~/VeriForge

# Remove launchers
rm $PREFIX/bin/veriforge-red
rm $PREFIX/bin/veriforge-dashboard
rm $PREFIX/bin/veriforge-privacy
rm $PREFIX/bin/veriforge-sdk

# Remove shortcuts
rm -f ~/.shortcuts/VeriForge-Scan
rm -f ~/.termux/tasker/veriforge-scan.sh

# Remove Python packages
pip uninstall veriforge-sdk veriforge-red -y
```

---

## License

VeriForge is distributed under the MIT License.

---

*Last updated: 2024 — VeriForge v1.0.0*

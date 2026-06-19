# VeriForge Red

**Local-First Security Sentinel for Developers and Everyday Users**

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-93%20passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android-blueviolet)]()

---

## What is VeriForge Red?

VeriForge Red is a **local-first, cross-platform security application** that runs on your device — not in the cloud. It combines the power of the VeriForge hardened verification engine with continuous monitoring, privacy auditing, threat quarantine, and auto-remediation.

### Zero Cloud. Zero Telemetry. Zero Accounts.

Everything runs locally on your machine. Your code never leaves your device. No accounts, no subscriptions, no data collection.

---

## Features

| Feature | What It Does |
|---------|-------------|
| **Code Security Scanning** | Full adversarial scans with VeriClaw — 7 payload types, 8 mutation strategies, formal property proving |
| **Privacy Protection** | Audit system privacy settings — detect data leaks, fix telemetry, preserve your digital footprint |
| **Threat Quarantine** | Isolate suspicious files with AES-256 encryption. Safe restore. Secure delete. |
| **Auto-Remediation** | One-click fixes for vulnerabilities. Harden privacy settings automatically. |
| **Developer Vault** | Encrypted storage for sensitive code, API keys, credentials. PBKDF2 password protection. |
| **Background Monitoring** | Continuous file system watching. Real-time threat detection. Scheduled scans. |

---

## Platform Support

| Platform | Status | Download |
|----------|--------|----------|
| **Windows** | Ready | `.exe` installer (45MB) |
| **Android** | Ready | `.apk` (25MB) |
| **Linux** | Core engine works | Source install |
| **macOS** | Core engine works | Source install |

---

## Quick Start

### Windows

1. Download `VeriForgeRed-Setup.exe` from [veriforge.dev/red](https://veriforge.dev/red)
2. Run the installer
3. VeriForge Red starts in your system tray
4. Right-click the red shield icon to scan, monitor, or open the full app

### Android

1. Download `VeriForgeRed.apk` from [veriforge.dev/red](https://veriforge.dev/red)
2. Enable "Install from unknown sources" temporarily
3. Install and grant permissions
4. VeriForge Red runs as a foreground service with persistent notification

### Python (All Platforms)

```bash
pip install veriforge-red

# Run the core engine
python -m veriforge_red.core.engine

# Launch the desktop GUI (Windows/Linux)
python -m veriforge_red.desktop
```

---

## Architecture

```
Your Device
    |
    v
+----------------------------------+
|  VeriForge Red Engine            |
|  + Scanner (file watch + scans)  |
|  + PrivacyAuditor (OS settings)  |
|  + ThreatDetector (7 patterns)   |
|  + Quarantine (AES-256 encrypt)  |
|  + Remediation (auto-fix)        |
|  + Vault (PBKDF2 encrypt)        |
|  + Monitor (background loop)     |
+----------------------------------+
    |              |              |
    v              v              v
+--------+ +------------+ +-------------+
|Windows | |  Android   | |   Python    |
|Desktop | |    App     | |   CLI/GUI   |
|(.exe)  | |   (.apk)   | |  (source)   |
+--------+ +------------+ +-------------+
    |              |              |
    v              v              v
+--------+ +------------+ +-------------+
|System  | | Foreground | |  Terminal   |
| Tray   | |  Service   | |   Output    |
|Service | |Notification| |             |
+--------+ +------------+ +-------------+
```

---

## Built on VeriForge

VeriForge Red is built on the hardened VeriForge platform:

- **12 CVEs patched** — No eval(), immutable audit logs, HMAC signatures, JWT+RBAC
- **VeriClaw** — Adversarial security testing with 327 passing tests
- **Formal verification** — Type safety, memory safety, injection resistance proofs
- **Agent swarms** — Byzantine fault tolerant consensus

---

## CLI Usage

```bash
# Scan a file or directory
veriforge-red scan --target ./my_project

# Quick scan (syntax + semantic only)
veriforge-red scan --target ./myapp.py --quick

# Deep scan (all layers + mutations + proofs)
veriforge-red scan --target ./my_project --deep

# Start background monitoring
veriforge-red monitor --start

# Check privacy score
veriforge-red privacy --audit

# View dashboard
veriforge-red dashboard
```

---

## Privacy Promise

**We can't see your code. We can't see your data. We literally can't.**

- No network connections — everything is local
- No telemetry or analytics
- No accounts or sign-ups required
- No cloud processing
- Open source (MIT License) — verify it yourself

---

## Building from Source

### Windows .exe

```bash
cd veriforge_red/build
python build_windows.py
# Output: dist/VeriForgeRed.exe, dist/VeriForgeRedService.exe
```

### Android .apk

```bash
cd veriforge_red/build
./build_android.sh
# Output: bin/VeriForgeRed-1.0.0-arm64-v8a.apk
```

### Website

```bash
cd veriforge_red/website
# Open index.html in any browser, or deploy as static site
```

---

## Documentation

- [Build Guide](veriforge_red/build/README.md) — Build instructions for all platforms
- [VeriClaw API](https://github.com/veriforge/vericlaw/blob/main/docs/API.md) — Core security engine API
- [Security Policy](SECURITY.md) — Vulnerability reporting

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT License — see [LICENSE](LICENSE).

---

**VeriForge Red** — *Your code's guardian. Your privacy's shield. Local-first. Always.*

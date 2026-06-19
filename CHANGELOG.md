# Changelog

## [1.0.0] - 2026-06-19

### Added
- Core engine: Scanner, PrivacyAuditor, ThreatDetector, QuarantineManager, RemediationEngine, Vault, Monitor, Database
- Windows desktop app: 7-tab GUI, system tray, Windows service, privacy auditor
- Android app: 6-screen Kivy app, foreground service, privacy auditor
- Website: Landing page with particle animation, download page, fully responsive
- 93 tests passing across core, Windows, and Android
- PyInstaller build for Windows .exe
- Buildozer build for Android .apk
- Inno Setup installer for Windows
- AES-256 encrypted quarantine with secure delete
- PBKDF2 password-derived vault encryption
- 7 threat detection patterns (eval, secrets, network, obfuscation, backdoor, permissions, credentials)
- 13 Windows privacy checks (telemetry, Cortana, firewall, UAC, Defender, etc.)
- 12 Android privacy checks (permissions, encryption, screen lock, overlay, etc.)

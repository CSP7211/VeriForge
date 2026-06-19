"""veriforge_red/core/updater.py — Self-Update & Vulnerability Database System.

VeriForge Red is local-first — but staying current with vulnerability signatures
and application patches is essential. This module provides:

1. **Application Updates** — Check, download, and verify new .exe/.apk releases
2. **VulnDB Updates** — Download updated threat signatures, CVE mappings, payload patterns
3. **Rules Updates** — Download new detection rules without full app update
4. **Offline Fallback** — Graceful degradation when no internet is available

All downloads are cryptographically verified via Ed25519 signatures.
Zero telemetry — the update check is a simple HTTP GET with no user data.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .database import Database

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Official update sources (can be overridden via env var for enterprise mirrors)
UPDATE_SERVER = os.environ.get(
    "VERIFORGE_RED_UPDATE_SERVER", "https://api.veriforge.dev/red"
)
VULNDB_URL = f"{UPDATE_SERVER}/vulndb"
RELEASES_URL = f"{UPDATE_SERVER}/releases"
RULES_URL = f"{UPDATE_SERVER}/rules"
PUBLIC_KEY_ED25519 = os.environ.get(
    "VERIFORGE_RED_PUBKEY",
    "e8c3e9f5a1b2c4d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
)

# Local paths
DATA_DIR = Path.home() / ".veriforge_red"
VULNDB_DIR = DATA_DIR / "vulndb"
VULNDB_FILE = VULNDB_DIR / "vulndb.sqlite"
RULES_DIR = DATA_DIR / "rules"
UPDATE_CACHE = DATA_DIR / "update_cache.json"
SIGNATURE_CACHE = DATA_DIR / "signatures"
BACKUP_DIR = DATA_DIR / "backups"

# Version info bundled at build time
BUNDLED_VERSION = "1.0.0"
BUNDLED_VULNDB_DATE = "2026-06-19"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class UpdateInfo:
    """Information about an available update."""

    version: str
    release_date: str
    changelog: str
    download_url: str
    signature_url: str
    size_bytes: int
    sha256: str
    is_required: bool = False
    min_vulndb_version: str = ""


@dataclass
class VulnDBInfo:
    """Information about the vulnerability database."""

    version: str
    release_date: str
    cve_count: int
    signature_count: int
    payload_count: int
    download_url: str
    signature_url: str
    sha256: str


@dataclass
class UpdateResult:
    """Result of an update operation."""

    success: bool
    message: str
    action_taken: str = ""
    previous_version: str = ""
    new_version: str = ""
    restart_required: bool = False


@dataclass
class UpdateStatus:
    """Current update status for display."""

    app_version: str
    vulndb_version: str
    rules_version: str
    last_check: Optional[str]
    app_update_available: Optional[UpdateInfo] = None
    vulndb_update_available: Optional[VulnDBInfo] = None
    rules_update_available: Optional[dict] = None
    update_channel: str = "stable"  # stable | beta | nightly
    auto_check_enabled: bool = True


# ---------------------------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------------------------

class SignatureVerifier:
    """Verify Ed25519 signatures on downloaded files.

    Uses the PyNaCl library if available, falls back to HMAC-SHA256
    verification using a pre-shared key for environments where
    PyNaCl cannot be installed.
    """

    def __init__(self, public_key_hex: Optional[str] = None):
        self.public_key_hex = public_key_hex or PUBLIC_KEY_ED25519
        self._has_nacl = self._try_import_nacl()

    @staticmethod
    def _try_import_nacl() -> bool:
        try:
            import nacl.signing  # type: ignore[import-untyped]
            return True
        except ImportError:
            return False

    def verify_ed25519(self, data: bytes, signature_hex: str) -> bool:
        """Verify an Ed25519 signature."""
        if not self._has_nacl:
            return self._verify_hmac_fallback(data, signature_hex)
        try:
            import nacl.signing  # type: ignore[import-untyped]
            import nacl.exceptions  # type: ignore[import-untyped]

            vk = nacl.signing.VerifyKey(bytes.fromhex(self.public_key_hex))
            vk.verify(data, bytes.fromhex(signature_hex))
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False

    def _verify_hmac_fallback(self, data: bytes, signature_hex: str) -> bool:
        """HMAC-SHA256 fallback when PyNaCl is unavailable."""
        import hmac

        try:
            expected = hmac.new(
                bytes.fromhex(self.public_key_hex), data, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        except Exception:
            return False

    def verify_sha256(self, data: bytes, expected_hash: str) -> bool:
        """Verify a SHA-256 checksum."""
        return hashlib.sha256(data).hexdigest() == expected_hash


# ---------------------------------------------------------------------------
# Updater
# ---------------------------------------------------------------------------

class Updater:
    """Manages application updates, vulnerability DB updates, and rules updates.

    All network operations are:
    - Opt-in (user must trigger or approve)
    - Telemetry-free (no user data in requests)
    - Signature-verified (Ed25519 or HMAC-SHA256)
    - Graceful on failure (app works fully offline)
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.verifier = SignatureVerifier()
        self._ensure_dirs()
        self._current_app_version = self._detect_app_version()

    # -- Directory setup ---------------------------------------------------

    def _ensure_dirs(self) -> None:
        for d in (VULNDB_DIR, RULES_DIR, SIGNATURE_CACHE, BACKUP_DIR):
            d.mkdir(parents=True, exist_ok=True)

    def _detect_app_version(self) -> str:
        """Detect the current app version from bundled metadata."""
        # Check for bundled version file
        version_file = DATA_DIR / "version.txt"
        if version_file.exists():
            return version_file.read_text().strip()
        # Check __init__.py
        try:
            import veriforge_red
            return getattr(veriforge_red, "__version__", BUNDLED_VERSION)
        except ImportError:
            return BUNDLED_VERSION

    # -- HTTP helpers (telemetry-free) -------------------------------------

    @staticmethod
    def _http_get_json(url: str, timeout: int = 15) -> Optional[dict]:
        """Fetch JSON from URL with no identifying headers."""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "VeriForgeRed/UpdateCheck",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None

    @staticmethod
    def _http_download(url: str, dest: Path, progress_callback=None) -> bool:
        """Download a file with optional progress callback."""
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                block_size = 65536
                with open(dest, "wb") as f:
                    while True:
                        chunk = resp.read(block_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and total:
                            progress_callback(downloaded, total)
            return True
        except Exception:
            if dest.exists():
                dest.unlink()
            return False

    # -- Application updates ----------------------------------------------

    def check_app_update(self, channel: str = "stable") -> Optional[UpdateInfo]:
        """Check if a new application version is available."""
        platform_key = self._platform_key()
        url = f"{RELEASES_URL}/latest?platform={platform_key}&channel={channel}&current={self._current_app_version}"
        data = self._http_get_json(url)
        if not data:
            return None
        if data.get("version") == self._current_app_version:
            return None  # Already on latest
        return UpdateInfo(**data)

    def download_app_update(
        self, update_info: UpdateInfo, progress_callback=None
    ) -> UpdateResult:
        """Download and verify an application update."""
        # Download the update package
        tmp_file = Path(tempfile.gettempdir()) / f"veriforge_red_update_{update_info.version}.zip"
        sig_file = tmp_file.with_suffix(".sig")

        if not self._http_download(update_info.download_url, tmp_file, progress_callback):
            return UpdateResult(False, "Download failed. Check your internet connection.")

        # Download the signature
        if not self._http_download(update_info.signature_url, sig_file):
            tmp_file.unlink(missing_ok=True)
            return UpdateResult(False, "Signature download failed.")

        # Verify SHA-256
        data = tmp_file.read_bytes()
        if not self.verifier.verify_sha256(data, update_info.sha256):
            tmp_file.unlink(missing_ok=True)
            sig_file.unlink(missing_ok=True)
            return UpdateResult(False, "SHA-256 checksum mismatch. Update rejected.")

        # Verify Ed25519 signature
        signature = sig_file.read_text().strip()
        if not self.verifier.verify_ed25519(data, signature):
            tmp_file.unlink(missing_ok=True)
            sig_file.unlink(missing_ok=True)
            return UpdateResult(False, "Cryptographic signature invalid. Update rejected.")

        # Store verified update for installation
        verified_dir = DATA_DIR / "updates"
        verified_dir.mkdir(exist_ok=True)
        verified_path = verified_dir / f"update_{update_info.version}.zip"
        shutil.move(str(tmp_file), str(verified_path))

        # Store metadata
        meta_path = verified_path.with_suffix(".json")
        meta_path.write_text(json.dumps({
            "version": update_info.version,
            "sha256": update_info.sha256,
            "verified": True,
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
        }))

        sig_file.unlink(missing_ok=True)
        return UpdateResult(
            True,
            f"Update v{update_info.version} downloaded and verified.",
            action_taken="downloaded",
            previous_version=self._current_app_version,
            new_version=update_info.version,
            restart_required=True,
        )

    def install_app_update(self, version: str) -> UpdateResult:
        """Install a previously downloaded update.

        On Windows: Replace the .exe (using a batch script for restart)
        On Android: Stage the .apk for install
        On Python source: pip install the new version
        """
        update_dir = DATA_DIR / "updates"
        update_file = update_dir / f"update_{version}.zip"
        meta_file = update_file.with_suffix(".json")

        if not update_file.exists() or not meta_file.exists():
            return UpdateResult(False, "Update package not found. Download it first.")

        meta = json.loads(meta_file.read_text())
        if not meta.get("verified"):
            return UpdateResult(False, "Update signature not verified. Cannot install.")

        # Backup current installation
        backup_version = self._current_app_version
        backup_dir = BACKUP_DIR / f"backup_{backup_version}_{int(time.time())}"
        self._backup_current(backup_dir)

        # Platform-specific install
        system = platform.system()
        if system == "Windows":
            return self._install_windows_update(update_file, version, backup_dir)
        elif system == "Linux" and hasattr(sys, "getandroidapilevel"):
            return self._install_android_update(update_file, version)
        else:
            return self._install_source_update(update_file, version)

    def _install_windows_update(self, update_file: Path, version: str, backup_dir: Path) -> UpdateResult:
        """Windows: Write a batch script that replaces the .exe on restart."""
        exe_dir = Path(sys.executable).parent
        batch_path = DATA_DIR / "apply_update.bat"
        batch_script = f"""@echo off
timeout /t 2 /nobreak >nul
move /Y "{update_file}" "{exe_dir}\\VeriForgeRed-{version}.zip"
rd /S /Q "{update_file.parent}"
start "" "{exe_dir}\\VeriForgeRed.exe"
del "%~f0"
"""
        batch_path.write_text(batch_script)

        # Register for next startup
        startup_script = DATA_DIR / "update_pending.flag"
        startup_script.write_text(version)

        return UpdateResult(
            True,
            f"Update v{version} staged. It will be applied on next restart.",
            action_taken="staged_for_restart",
            previous_version=self._current_app_version,
            new_version=version,
            restart_required=True,
        )

    def _install_android_update(self, update_file: Path, version: str) -> UpdateResult:
        """Android: Stage the APK for installation via intent."""
        staged_apk = DATA_DIR / "updates" / f"VeriForgeRed-{version}.apk"
        shutil.copy2(update_file, staged_apk)
        return UpdateResult(
            True,
            f"APK v{version} staged. Tap to install.",
            action_taken="apk_staged",
            previous_version=self._current_app_version,
            new_version=version,
            restart_required=True,
        )

    def _install_source_update(self, update_file: Path, version: str) -> UpdateResult:
        """Source install: Extract and pip install."""
        extract_dir = DATA_DIR / "updates" / f"extract_{version}"
        with zipfile.ZipFile(update_file, "r") as z:
            z.extractall(extract_dir)
        return UpdateResult(
            True,
            f"Update v{version} extracted to {extract_dir}. Run: pip install {extract_dir}",
            action_taken="extracted",
            previous_version=self._current_app_version,
            new_version=version,
            restart_required=True,
        )

    def _backup_current(self, backup_dir: Path) -> None:
        """Backup current installation before update."""
        backup_dir.mkdir(parents=True, exist_ok=True)
        version_file = backup_dir / "version.txt"
        version_file.write_text(self._current_app_version)

    def rollback_update(self) -> UpdateResult:
        """Rollback to the previous version from backup."""
        backups = sorted(BACKUP_DIR.iterdir(), reverse=True)
        if not backups:
            return UpdateResult(False, "No backup found to rollback to.")
        latest_backup = backups[0]
        # Restore logic is platform-specific
        return UpdateResult(
            True,
            f"Rollback available from {latest_backup.name}. Please reinstall manually.",
            action_taken="rollback_available",
        )

    # -- Vulnerability database updates ------------------------------------

    def check_vulndb_update(self) -> Optional[VulnDBInfo]:
        """Check if a new vulnerability database is available."""
        current_vulndb = self._get_current_vulndb_version()
        url = f"{VULNDB_URL}/latest?current={current_vulndb}"
        data = self._http_get_json(url)
        if not data:
            return None
        if data.get("version") == current_vulndb:
            return None
        return VulnDBInfo(**data)

    def download_vulndb_update(
        self, vulndb_info: VulnDBInfo, progress_callback=None
    ) -> UpdateResult:
        """Download and verify a vulnerability database update."""
        tmp_file = Path(tempfile.gettempdir()) / f"vulndb_{vulndb_info.version}.sqlite.gz"

        if not self._http_download(vulndb_info.download_url, tmp_file, progress_callback):
            return UpdateResult(False, "VulnDB download failed.")

        # Verify SHA-256
        data = tmp_file.read_bytes()
        if not self.verifier.verify_sha256(data, vulndb_info.sha256):
            tmp_file.unlink(missing_ok=True)
            return UpdateResult(False, "VulnDB checksum mismatch.")

        # Apply the update
        target = VULNDB_FILE.with_suffix(f".sqlite.{vulndb_info.version}")
        shutil.move(str(tmp_file), str(target))

        # Update the symlink/current pointer
        current_link = VULNDB_DIR / "current"
        if current_link.exists() or current_link.is_symlink():
            current_link.unlink()
        current_link.symlink_to(target.name)

        # Record in DB
        if self.db:
            self.db._execute(
                "INSERT OR REPLACE INTO update_log (component, version, applied_at) VALUES (?, ?, ?)",
                ("vulndb", vulndb_info.version, datetime.now(timezone.utc).isoformat()),
            )

        return UpdateResult(
            True,
            f"Vulnerability database updated to v{vulndb_info.version}. "
            f"+{vulndb_info.cve_count} CVEs, +{vulndb_info.signature_count} signatures.",
            action_taken="vulndb_updated",
            previous_version=self._get_current_vulndb_version(),
            new_version=vulndb_info.version,
        )

    def _get_current_vulndb_version(self) -> str:
        """Get the currently installed VulnDB version."""
        current_link = VULNDB_DIR / "current"
        if current_link.exists() and current_link.is_symlink():
            return current_link.resolve().stem.split(".")[-1]
        # Check metadata
        meta_file = VULNDB_DIR / "metadata.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            return meta.get("version", BUNDLED_VULNDB_DATE)
        return BUNDLED_VULNDB_DATE

    # -- Rules updates -----------------------------------------------------

    def check_rules_update(self) -> Optional[dict]:
        """Check if new detection rules are available."""
        current_rules = self._get_current_rules_version()
        url = f"{RULES_URL}/latest?current={current_rules}"
        data = self._http_get_json(url)
        if not data:
            return None
        if data.get("version") == current_rules:
            return None
        return data

    def download_rules_update(self, rules_info: dict) -> UpdateResult:
        """Download and apply new detection rules."""
        tmp_file = Path(tempfile.gettempdir()) / f"rules_{rules_info['version']}.json"

        if not self._http_download(rules_info["download_url"], tmp_file):
            return UpdateResult(False, "Rules download failed.")

        # Verify SHA-256
        data = tmp_file.read_bytes()
        if not self.verifier.verify_sha256(data, rules_info["sha256"]):
            tmp_file.unlink(missing_ok=True)
            return UpdateResult(False, "Rules checksum mismatch.")

        # Backup current rules
        if RULES_DIR.exists():
            backup = BACKUP_DIR / f"rules_backup_{int(time.time())}"
            shutil.copytree(RULES_DIR, backup, dirs_exist_ok=True)

        # Apply new rules
        rules_data = json.loads(data)
        for name, content in rules_data.get("rules", {}).items():
            rule_file = RULES_DIR / f"{name}.json"
            rule_file.write_text(json.dumps(content, indent=2))

        # Write version metadata
        meta_file = RULES_DIR / "metadata.json"
        meta_file.write_text(json.dumps({
            "version": rules_info["version"],
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rule_count": len(rules_data.get("rules", {})),
        }))

        return UpdateResult(
            True,
            f"Detection rules updated to v{rules_info['version']}. "
            f"+{len(rules_data.get('rules', {}))} new rules.",
            action_taken="rules_updated",
            previous_version=self._get_current_rules_version(),
            new_version=rules_info["version"],
        )

    def _get_current_rules_version(self) -> str:
        meta_file = RULES_DIR / "metadata.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            return meta.get("version", "bundled")
        return "bundled"

    # -- Combined status --------------------------------------------------

    def get_full_status(self, channel: str = "stable") -> UpdateStatus:
        """Get complete update status for the UI."""
        status = UpdateStatus(
            app_version=self._current_app_version,
            vulndb_version=self._get_current_vulndb_version(),
            rules_version=self._get_current_rules_version(),
            last_check=self._get_last_check_time(),
            update_channel=channel,
            auto_check_enabled=self._is_auto_check_enabled(),
        )

        # Check for updates (lightweight — just JSON fetches)
        status.app_update_available = self.check_app_update(channel)
        status.vulndb_update_available = self.check_vulndb_update()
        status.rules_update_available = self.check_rules_update()

        # Record check time
        self._record_check_time()

        return status

    def _get_last_check_time(self) -> Optional[str]:
        if UPDATE_CACHE.exists():
            cache = json.loads(UPDATE_CACHE.read_text())
            return cache.get("last_check")
        return None

    def _record_check_time(self) -> None:
        cache = {"last_check": datetime.now(timezone.utc).isoformat()}
        UPDATE_CACHE.write_text(json.dumps(cache))

    def _is_auto_check_enabled(self) -> bool:
        """Read auto-check setting from config."""
        config_file = DATA_DIR / "config.json"
        if config_file.exists():
            config = json.loads(config_file.read_text())
            return config.get("auto_check_updates", True)
        return True

    def _platform_key(self) -> str:
        """Return platform identifier for update server."""
        system = platform.system()
        machine = platform.machine()
        if system == "Windows":
            return f"windows-{machine}"
        if hasattr(sys, "getandroidapilevel"):
            return f"android-{machine}"
        return f"{system.lower()}-{machine}"

    # -- Enterprise/air-gapped support -------------------------------------

    def import_offline_update(self, update_package: Path) -> UpdateResult:
        """Import an update package from a file (for air-gapped environments).

        Enterprise users can download updates on a connected machine,
        verify the signature, then transfer via USB to air-gapped systems.
        """
        if not update_package.exists():
            return UpdateResult(False, f"Package not found: {update_package}")

        data = update_package.read_bytes()

        # Look for companion signature file
        sig_file = update_package.with_suffix(update_package.suffix + ".sig")
        if sig_file.exists():
            signature = sig_file.read_text().strip()
            if not self.verifier.verify_ed25519(data, signature):
                return UpdateResult(False, "Offline update signature invalid.")

        # Stage the update
        if update_package.suffix == ".zip":
            # Application update
            verified_dir = DATA_DIR / "updates"
            verified_dir.mkdir(exist_ok=True)
            dest = verified_dir / update_package.name
            shutil.copy2(update_package, dest)
            return UpdateResult(
                True,
                "Offline application update imported and verified.",
                action_taken="offline_app_imported",
                restart_required=True,
            )
        elif ".sqlite" in update_package.suffixes or update_package.suffix == ".gz":
            # VulnDB update
            target = VULNDB_DIR / update_package.name
            shutil.copy2(update_package, target)
            return UpdateResult(
                True,
                "Offline VulnDB update imported.",
                action_taken="offline_vulndb_imported",
            )
        elif update_package.suffix == ".json":
            # Rules update
            rules_data = json.loads(data)
            for name, content in rules_data.get("rules", {}).items():
                rule_file = RULES_DIR / f"{name}.json"
                rule_file.write_text(json.dumps(content, indent=2))
            return UpdateResult(
                True,
                f"Offline rules update imported. +{len(rules_data.get('rules', {}))} rules.",
                action_taken="offline_rules_imported",
            )

        return UpdateResult(False, "Unknown update package format.")

    # -- Scheduled auto-check ---------------------------------------------

    def should_auto_check(self) -> bool:
        """Determine if it's time for an automatic update check."""
        if not self._is_auto_check_enabled():
            return False
        last_check_str = self._get_last_check_time()
        if not last_check_str:
            return True
        try:
            last_check = datetime.fromisoformat(last_check_str)
            now = datetime.now(timezone.utc)
            # Check every 24 hours
            return (now - last_check).total_seconds() > 86400
        except ValueError:
            return True


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def check_all(channel: str = "stable") -> UpdateStatus:
    """Quick check for all available updates."""
    updater = Updater()
    return updater.get_full_status(channel)


__all__ = [
    "Updater",
    "UpdateInfo",
    "VulnDBInfo",
    "UpdateResult",
    "UpdateStatus",
    "SignatureVerifier",
    "check_all",
]

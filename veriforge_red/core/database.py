"""SQLite database for local storage — thread-safe with locking.

Six tables manage the full lifecycle of security data:
- scans          : scan history
- threats        : detected threats
- quarantine     : quarantined items
- privacy_issues : privacy audit results
- vault_items    : vault entries
- remediation_log: auto-fix history
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL: str = """
-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    grade       TEXT    NOT NULL DEFAULT 'F',
    risk_score  REAL    NOT NULL DEFAULT 0.0,
    timestamp   TEXT    NOT NULL,
    findings_json TEXT  NOT NULL DEFAULT '[]'
);

-- Detected threats
CREATE TABLE IF NOT EXISTS threats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT    NOT NULL,
    threat_type     TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'medium',
    status          TEXT    NOT NULL DEFAULT 'active',
    quarantine_path TEXT,
    timestamp       TEXT    NOT NULL
);

-- Quarantined items
CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantine_id   TEXT    NOT NULL UNIQUE,
    original_path   TEXT    NOT NULL,
    quarantine_path TEXT    NOT NULL,
    encryption_key  TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    restored        INTEGER NOT NULL DEFAULT 0
);

-- Privacy audit results
CREATE TABLE IF NOT EXISTS privacy_issues (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    category          TEXT    NOT NULL,
    setting_name      TEXT    NOT NULL,
    current_value     TEXT    NOT NULL DEFAULT '',
    recommended_value TEXT    NOT NULL DEFAULT '',
    severity          TEXT    NOT NULL DEFAULT 'medium',
    description       TEXT    NOT NULL DEFAULT '',
    cwe_id            TEXT,
    timestamp         TEXT    NOT NULL
);

-- Vault entries
CREATE TABLE IF NOT EXISTS vault_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id        TEXT    NOT NULL UNIQUE,
    original_path   TEXT    NOT NULL,
    encrypted_path  TEXT    NOT NULL,
    added_at        TEXT    NOT NULL
);

-- Auto-fix history
CREATE TABLE IF NOT EXISTS remediation_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_type   TEXT    NOT NULL,
    file_path    TEXT    NOT NULL DEFAULT '',
    action_taken TEXT    NOT NULL,
    success      INTEGER NOT NULL DEFAULT 0,
    timestamp    TEXT    NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Dataclass helpers
# ---------------------------------------------------------------------------

@dataclass
class ScanRecord:
    id: int
    target: str
    grade: str
    risk_score: float
    timestamp: str
    findings: list[dict] = field(default_factory=list)


@dataclass
class ThreatRecord:
    id: int
    file_path: str
    threat_type: str
    severity: str
    status: str
    quarantine_path: Optional[str]
    timestamp: str


@dataclass
class QuarantineRecord:
    id: int
    quarantine_id: str
    original_path: str
    quarantine_path: str
    encryption_key: str
    timestamp: str
    restored: bool


@dataclass
class PrivacyIssueRecord:
    id: int
    category: str
    setting_name: str
    current_value: str
    recommended_value: str
    severity: str
    description: str
    cwe_id: Optional[str]
    timestamp: str


@dataclass
class VaultItemRecord:
    id: int
    vault_id: str
    original_path: str
    encrypted_path: str
    added_at: str


@dataclass
class RemediationLogRecord:
    id: int
    issue_type: str
    file_path: str
    action_taken: str
    success: bool
    timestamp: str


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class Database:
    """Thread-safe SQLite database manager for VeriForge Red."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            home = Path.home()
            data_dir = home / ".veriforge_red"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(data_dir / "veriforge_red.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()
        self._init_schema()

    # -- connection management (one per thread) ---------------------------

    def _conn(self) -> sqlite3.Connection:
        """Return a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # autocommit mode for simplicity
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn.execute("PRAGMA foreign_keys=ON;")
        return self._local.conn

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # -- schema -----------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            self._conn().executescript(_SCHEMA_SQL)

    # -- generic helpers --------------------------------------------------

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _insert(self, sql: str, params: tuple) -> int:
        with self._lock:
            cur = self._conn().execute(sql, params)
            return cur.lastrowid or 0

    def _query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            cur = self._conn().execute(sql, params)
            return cur.fetchone()

    def _query_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn().execute(sql, params)
            return cur.fetchall()

    # -- scans CRUD -------------------------------------------------------

    def insert_scan(self, target: str, grade: str, risk_score: float,
                    findings: list[dict]) -> int:
        return self._insert(
            "INSERT INTO scans (target, grade, risk_score, timestamp, findings_json) VALUES (?, ?, ?, ?, ?)",
            (target, grade, risk_score, self._now(), json.dumps(findings)),
        )

    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        row = self._query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if row is None:
            return None
        return ScanRecord(
            id=row["id"],
            target=row["target"],
            grade=row["grade"],
            risk_score=row["risk_score"],
            timestamp=row["timestamp"],
            findings=json.loads(row["findings_json"]),
        )

    def get_all_scans(self, limit: int = 100) -> list[ScanRecord]:
        rows = self._query_all(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [
            ScanRecord(
                id=r["id"], target=r["target"], grade=r["grade"],
                risk_score=r["risk_score"], timestamp=r["timestamp"],
                findings=json.loads(r["findings_json"]),
            )
            for r in rows
        ]

    def delete_scan(self, scan_id: int) -> bool:
        with self._lock:
            cur = self._conn().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    # -- threats CRUD -----------------------------------------------------

    def insert_threat(self, file_path: str, threat_type: str,
                      severity: str = "medium", status: str = "active",
                      quarantine_path: Optional[str] = None) -> int:
        return self._insert(
            "INSERT INTO threats (file_path, threat_type, severity, status, quarantine_path, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (file_path, threat_type, severity, status, quarantine_path, self._now()),
        )

    def get_threat(self, threat_id: int) -> Optional[ThreatRecord]:
        row = self._query_one("SELECT * FROM threats WHERE id = ?", (threat_id,))
        if row is None:
            return None
        return ThreatRecord(
            id=row["id"], file_path=row["file_path"], threat_type=row["threat_type"],
            severity=row["severity"], status=row["status"],
            quarantine_path=row["quarantine_path"], timestamp=row["timestamp"],
        )

    def get_all_threats(self, status: Optional[str] = None,
                        limit: int = 100) -> list[ThreatRecord]:
        sql = "SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?"
        params: tuple = (limit,)
        if status:
            sql = "SELECT * FROM threats WHERE status = ? ORDER BY timestamp DESC LIMIT ?"
            params = (status, limit)
        rows = self._query_all(sql, params)
        return [
            ThreatRecord(
                id=r["id"], file_path=r["file_path"], threat_type=r["threat_type"],
                severity=r["severity"], status=r["status"],
                quarantine_path=r["quarantine_path"], timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def update_threat_status(self, threat_id: int, status: str) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "UPDATE threats SET status = ? WHERE id = ?", (status, threat_id)
            )
            return cur.rowcount > 0

    def delete_threat(self, threat_id: int) -> bool:
        with self._lock:
            cur = self._conn().execute("DELETE FROM threats WHERE id = ?", (threat_id,))
            return cur.rowcount > 0

    # -- quarantine CRUD --------------------------------------------------

    def insert_quarantine(self, quarantine_id: str, original_path: str,
                          quarantine_path: str, encryption_key: str) -> int:
        return self._insert(
            "INSERT INTO quarantine (quarantine_id, original_path, quarantine_path, encryption_key, timestamp, restored) VALUES (?, ?, ?, ?, ?, 0)",
            (quarantine_id, original_path, quarantine_path, encryption_key, self._now()),
        )

    def get_quarantine(self, quarantine_id: str) -> Optional[QuarantineRecord]:
        row = self._query_one(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        if row is None:
            return None
        return QuarantineRecord(
            id=row["id"], quarantine_id=row["quarantine_id"],
            original_path=row["original_path"], quarantine_path=row["quarantine_path"],
            encryption_key=row["encryption_key"], timestamp=row["timestamp"],
            restored=bool(row["restored"]),
        )

    def get_all_quarantine(self) -> list[QuarantineRecord]:
        rows = self._query_all("SELECT * FROM quarantine ORDER BY timestamp DESC")
        return [
            QuarantineRecord(
                id=r["id"], quarantine_id=r["quarantine_id"],
                original_path=r["original_path"], quarantine_path=r["quarantine_path"],
                encryption_key=r["encryption_key"], timestamp=r["timestamp"],
                restored=bool(r["restored"]),
            )
            for r in rows
        ]

    def mark_restored(self, quarantine_id: str) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "UPDATE quarantine SET restored = 1 WHERE quarantine_id = ?",
                (quarantine_id,),
            )
            return cur.rowcount > 0

    def delete_quarantine(self, quarantine_id: str) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "DELETE FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
            )
            return cur.rowcount > 0

    # -- privacy_issues CRUD ----------------------------------------------

    def insert_privacy_issue(self, category: str, setting_name: str,
                             current_value: str, recommended_value: str,
                             severity: str = "medium", description: str = "",
                             cwe_id: Optional[str] = None) -> int:
        return self._insert(
            "INSERT INTO privacy_issues (category, setting_name, current_value, recommended_value, severity, description, cwe_id, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (category, setting_name, current_value, recommended_value,
             severity, description, cwe_id, self._now()),
        )

    def get_privacy_issue(self, issue_id: int) -> Optional[PrivacyIssueRecord]:
        row = self._query_one(
            "SELECT * FROM privacy_issues WHERE id = ?", (issue_id,)
        )
        if row is None:
            return None
        return PrivacyIssueRecord(
            id=row["id"], category=row["category"], setting_name=row["setting_name"],
            current_value=row["current_value"], recommended_value=row["recommended_value"],
            severity=row["severity"], description=row["description"],
            cwe_id=row["cwe_id"], timestamp=row["timestamp"],
        )

    def get_all_privacy_issues(self, limit: int = 100) -> list[PrivacyIssueRecord]:
        rows = self._query_all(
            "SELECT * FROM privacy_issues ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [
            PrivacyIssueRecord(
                id=r["id"], category=r["category"], setting_name=r["setting_name"],
                current_value=r["current_value"], recommended_value=r["recommended_value"],
                severity=r["severity"], description=r["description"],
                cwe_id=r["cwe_id"], timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def delete_privacy_issue(self, issue_id: int) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "DELETE FROM privacy_issues WHERE id = ?", (issue_id,)
            )
            return cur.rowcount > 0

    # -- vault_items CRUD -------------------------------------------------

    def insert_vault_item(self, vault_id: str, original_path: str,
                          encrypted_path: str) -> int:
        return self._insert(
            "INSERT INTO vault_items (vault_id, original_path, encrypted_path, added_at) VALUES (?, ?, ?, ?)",
            (vault_id, original_path, encrypted_path, self._now()),
        )

    def get_vault_item(self, vault_id: str) -> Optional[VaultItemRecord]:
        row = self._query_one(
            "SELECT * FROM vault_items WHERE vault_id = ?", (vault_id,)
        )
        if row is None:
            return None
        return VaultItemRecord(
            id=row["id"], vault_id=row["vault_id"],
            original_path=row["original_path"], encrypted_path=row["encrypted_path"],
            added_at=row["added_at"],
        )

    def get_all_vault_items(self) -> list[VaultItemRecord]:
        rows = self._query_all("SELECT * FROM vault_items ORDER BY added_at DESC")
        return [
            VaultItemRecord(
                id=r["id"], vault_id=r["vault_id"],
                original_path=r["original_path"], encrypted_path=r["encrypted_path"],
                added_at=r["added_at"],
            )
            for r in rows
        ]

    def delete_vault_item(self, vault_id: str) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "DELETE FROM vault_items WHERE vault_id = ?", (vault_id,)
            )
            return cur.rowcount > 0

    # -- remediation_log CRUD ---------------------------------------------

    def insert_remediation(self, issue_type: str, file_path: str,
                           action_taken: str, success: bool = False) -> int:
        return self._insert(
            "INSERT INTO remediation_log (issue_type, file_path, action_taken, success, timestamp) VALUES (?, ?, ?, ?, ?)",
            (issue_type, file_path, action_taken, int(success), self._now()),
        )

    def get_remediation(self, log_id: int) -> Optional[RemediationLogRecord]:
        row = self._query_one(
            "SELECT * FROM remediation_log WHERE id = ?", (log_id,)
        )
        if row is None:
            return None
        return RemediationLogRecord(
            id=row["id"], issue_type=row["issue_type"], file_path=row["file_path"],
            action_taken=row["action_taken"], success=bool(row["success"]),
            timestamp=row["timestamp"],
        )

    def get_all_remediations(self) -> list[RemediationLogRecord]:
        rows = self._query_all(
            "SELECT * FROM remediation_log ORDER BY timestamp DESC"
        )
        return [
            RemediationLogRecord(
                id=r["id"], issue_type=r["issue_type"], file_path=r["file_path"],
                action_taken=r["action_taken"], success=bool(r["success"]),
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # -- stats helpers ----------------------------------------------------

    def get_threat_count(self) -> int:
        row = self._query_one(
            "SELECT COUNT(*) as cnt FROM threats WHERE status = 'active'"
        )
        return row["cnt"] if row else 0

    def get_quarantine_count(self) -> int:
        row = self._query_one(
            "SELECT COUNT(*) as cnt FROM quarantine WHERE restored = 0"
        )
        return row["cnt"] if row else 0

    def get_last_scan_time(self) -> Optional[str]:
        row = self._query_one(
            "SELECT timestamp FROM scans ORDER BY timestamp DESC LIMIT 1"
        )
        return row["timestamp"] if row else None

    def get_scan_count_last_7d(self) -> int:
        row = self._query_one(
            "SELECT COUNT(*) as cnt FROM scans WHERE timestamp >= datetime('now', '-7 days')"
        )
        return row["cnt"] if row else 0

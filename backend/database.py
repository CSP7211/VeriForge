"""
VeriForge Platform — Database Layer
SQLite with async support. Local-first: zero cloud, zero telemetry.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

DB_PATH = Path(__file__).parent.parent / "database" / "veriforge_platform.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
-- Users and auth
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin', 'viewer')),
    created_at  REAL DEFAULT (unixepoch())
);

-- Teams
CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    created_at  REAL DEFAULT (unixepoch())
);

-- Team memberships
CREATE TABLE IF NOT EXISTS team_members (
    team_id     INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT DEFAULT 'member' CHECK(role IN ('owner', 'admin', 'member')),
    joined_at   REAL DEFAULT (unixepoch()),
    PRIMARY KEY (team_id, user_id)
);

-- Projects (scan targets)
CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    source_type TEXT DEFAULT 'paste' CHECK(source_type IN ('paste', 'github', 'gitlab', 'upload', 'local')),
    source_url  TEXT,
    grade       TEXT DEFAULT 'A+',
    risk_score  REAL DEFAULT 0.0,
    last_scan_at REAL,
    created_at  REAL DEFAULT (unixepoch())
);

-- Scans
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    initiated_by INTEGER NOT NULL REFERENCES users(id),
    scanner     TEXT DEFAULT 'veriforge_security_scan'
        CHECK(scanner IN (
            'veriforge_security_scan',
            'veriforge_verify_code',
            'veriforge_check_compliance',
            'veriforge_audit_chain',
            'veriforge_generate_spec',
            'veriforge_generate_tests',
            'veriforge_explain_finding'
        )),
    status      TEXT DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'completed', 'failed')),
    grade       TEXT,
    risk_score  REAL,
    findings_count INTEGER DEFAULT 0,
    summary_json TEXT,
    started_at  REAL,
    completed_at REAL,
    created_at  REAL DEFAULT (unixepoch())
);

-- Findings (individual vulnerability findings)
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cwe         TEXT,
    fix         TEXT,
    line        INTEGER,
    matched     TEXT,
    status      TEXT DEFAULT 'open' CHECK(status IN ('open', 'resolved', 'false_positive', 'accepted')),
    assigned_to INTEGER REFERENCES users(id),
    created_at  REAL DEFAULT (unixepoch())
);

-- Compliance reports
CREATE TABLE IF NOT EXISTS compliance_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    standard    TEXT NOT NULL CHECK(standard IN ('SOC2', 'ISO27001', 'PCI-DSS')),
    score       REAL NOT NULL,
    checks_json TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    failed      INTEGER NOT NULL,
    created_at  REAL DEFAULT (unixepoch())
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    user_id     INTEGER REFERENCES users(id),
    project_id  INTEGER REFERENCES projects(id),
    details_json TEXT,
    hmac        TEXT,
    created_at  REAL DEFAULT (unixepoch())
);

-- API keys (for CI/CD integration)
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    scopes      TEXT DEFAULT 'scan:read,scan:write',
    last_used_at REAL,
    expires_at  REAL,
    created_at  REAL DEFAULT (unixepoch())
);

-- Scan schedules
CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanner     TEXT NOT NULL,
    cron_expr   TEXT NOT NULL,
    is_active   INTEGER DEFAULT 1,
    last_run_at REAL,
    next_run_at REAL,
    created_at  REAL DEFAULT (unixepoch())
);

-- Create default admin user (password: 'veriforge-admin')
INSERT OR IGNORE INTO users (id, username, email, password_hash, role) VALUES (
    1, 'admin', 'admin@veriforge.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA.qGZvKG6',
    'admin'
);

-- Create default team
INSERT OR IGNORE INTO teams (id, name, slug, owner_id) VALUES (
    1, 'Default Team', 'default', 1
);

-- Add admin to default team
INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (1, 1, 'owner');
"""


def get_db() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Initialize the database with schema."""
    conn = get_db()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_session():
    """Context manager for database sessions."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

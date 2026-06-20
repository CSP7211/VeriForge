"""
VeriForge Platform — FastAPI Backend
Security Operations Center API with all 7 product integrations.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from .database import db_session, init_db
from .auth import create_access_token, decode_token, verify_password, hash_password
from .scanner import get_engine

# ─── Init ──────────────────────────────────────────────────────────
app = FastAPI(
    title="VeriForge Platform API",
    description="Security Operations Center — Unified backend for all VeriForge products",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer(auto_error=False)

# Init DB on startup
@app.on_event("startup")
def _startup():
    init_db()


# ─── Models ────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""
    source_type: str = "paste"
    source_url: str = ""

class CreateScanRequest(BaseModel):
    project_id: int
    scanner: str = "veriforge_security_scan"
    code: str = ""
    standard: str = "SOC2"

class UpdateFindingRequest(BaseModel):
    status: str  # open, resolved, false_positive, accepted
    assigned_to: Optional[int] = None

class CreateTeamRequest(BaseModel):
    name: str
    slug: str

class CreateScheduleRequest(BaseModel):
    project_id: int
    scanner: str
    cron_expr: str


# ─── Auth Dependency ───────────────────────────────────────────────
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing token")
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    with db_session() as db:
        user = db.execute("SELECT * FROM users WHERE id = ?", (payload.get("sub"),)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return dict(user)


# ─── Auth Routes ───────────────────────────────────────────────────
@app.post("/api/auth/login")
def login(req: LoginRequest):
    with db_session() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
        if not user or not verify_password(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_access_token({"sub": str(user["id"]), "username": user["username"], "role": user["role"]})
        return {"access_token": token, "token_type": "bearer", "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}}

@app.post("/api/auth/register")
def register(req: CreateUserRequest):
    with db_session() as db:
        exists = db.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (req.username, req.email)).fetchone()
        if exists:
            raise HTTPException(status_code=400, detail="Username or email taken")
        pw_hash = hash_password(req.password)
        cursor = db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (req.username, req.email, pw_hash, req.role)
        )
        user_id = cursor.lastrowid
        token = create_access_token({"sub": str(user_id), "username": req.username, "role": req.role})
        return {"access_token": token, "user": {"id": user_id, "username": req.username, "role": req.role}}

@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}


# ─── Dashboard / Stats ─────────────────────────────────────────────
@app.get("/api/dashboard/stats")
def dashboard_stats(user=Depends(get_current_user)):
    with db_session() as db:
        total_projects = db.execute("SELECT COUNT(*) as c FROM projects").fetchone()["c"]
        total_scans = db.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
        total_findings = db.execute("SELECT COUNT(*) as c FROM findings WHERE status = 'open'").fetchone()["c"]
        critical_findings = db.execute("SELECT COUNT(*) as c FROM findings WHERE severity = 'critical' AND status = 'open'").fetchone()["c"]

        recent_scans = db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

        grade_distribution = db.execute(
            "SELECT grade, COUNT(*) as count FROM scans WHERE grade IS NOT NULL GROUP BY grade"
        ).fetchall()

        severity_distribution = db.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY severity"
        ).fetchall()

        return {
            "projects": total_projects,
            "scans": total_scans,
            "open_findings": total_findings,
            "critical_findings": critical_findings,
            "recent_scans": [dict(r) for r in recent_scans],
            "grade_distribution": [{"grade": r["grade"], "count": r["count"]} for r in grade_distribution],
            "severity_distribution": [{"severity": r["severity"], "count": r["count"]} for r in severity_distribution],
        }


# ─── Projects ──────────────────────────────────────────────────────
@app.get("/api/projects")
def list_projects(user=Depends(get_current_user)):
    with db_session() as db:
        rows = db.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        return {"projects": [dict(r) for r in rows]}

@app.post("/api/projects")
def create_project(req: CreateProjectRequest, user=Depends(get_current_user)):
    with db_session() as db:
        cursor = db.execute(
            "INSERT INTO projects (team_id, name, description, source_type, source_url) VALUES (?, ?, ?, ?, ?)",
            (1, req.name, req.description, req.source_type, req.source_url)
        )
        return {"id": cursor.lastrowid, **req.dict()}

@app.get("/api/projects/{project_id}")
def get_project(project_id: int, user=Depends(get_current_user)):
    with db_session() as db:
        row = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        scans = db.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC", (project_id,)).fetchall()
        findings = db.execute(
            "SELECT * FROM findings WHERE project_id = ? AND status = 'open' ORDER BY severity DESC",
            (project_id,)
        ).fetchall()
        return {"project": dict(row), "scans": [dict(s) for s in scans], "open_findings": [dict(f) for f in findings]}


# ─── Scans ─────────────────────────────────────────────────────────
@app.get("/api/scans")
def list_scans(user=Depends(get_current_user)):
    with db_session() as db:
        rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50").fetchall()
        return {"scans": [dict(r) for r in rows]}

@app.post("/api/scans")
async def create_scan(req: CreateScanRequest, user=Depends(get_current_user)):
    engine = get_engine()

    with db_session() as db:
        cursor = db.execute(
            "INSERT INTO scans (project_id, initiated_by, scanner, status, started_at) VALUES (?, ?, ?, ?, ?)",
            (req.project_id, user["id"], req.scanner, "running", time.time())
        )
        scan_id = cursor.lastrowid

    # Run the scan
    result = await engine.scan(req.scanner, req.code, standard=req.standard)

    # Store results
    with db_session() as db:
        scan_result = result.get("result", {})
        grade = scan_result.get("grade", "A+")
        risk_score = scan_result.get("risk_score", 0)
        findings = scan_result.get("findings", [])
        summary = scan_result.get("summary", {"total": len(findings)})

        db.execute(
            "UPDATE scans SET status = ?, grade = ?, risk_score = ?, findings_count = ?, summary_json = ?, completed_at = ? WHERE id = ?",
            ("completed", grade, risk_score, len(findings), json.dumps(summary), time.time(), scan_id)
        )

        # Insert findings
        for f in findings:
            db.execute(
                """INSERT INTO findings (scan_id, project_id, title, severity, cwe, fix, line, matched)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, req.project_id, f.get("title", ""), f.get("severity", "medium"),
                 f.get("cwe", ""), f.get("fix", ""), f.get("line", 0), f.get("matched", ""))
            )

        # Update project grade
        db.execute("UPDATE projects SET grade = ?, risk_score = ?, last_scan_at = ? WHERE id = ?",
                     (grade, risk_score, time.time(), req.project_id))

    return {"scan_id": scan_id, "status": "completed", "grade": grade, "risk_score": risk_score,
            "findings_count": len(findings), "result": result}

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, user=Depends(get_current_user)):
    with db_session() as db:
        scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        return {"scan": dict(scan), "findings": [dict(f) for f in findings]}


# ─── Pipeline ──────────────────────────────────────────────────────
@app.post("/api/pipeline")
async def run_pipeline(body: Dict[str, Any], user=Depends(get_current_user)):
    """Run the full security pipeline: scan + compliance + verify."""
    engine = get_engine()
    code = body.get("code", "")
    standards = body.get("standards", ["SOC2"])
    project_id = body.get("project_id", 1)

    if not code:
        raise HTTPException(status_code=400, detail="No code provided")

    result = await engine.run_pipeline(code, standards)

    # Store scan results
    with db_session() as db:
        cursor = db.execute(
            "INSERT INTO scans (project_id, initiated_by, scanner, status, grade, risk_score, findings_count, summary_json, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (project_id, user["id"], "pipeline", "completed", result["grade"], result["risk_score"],
             result["findings_count"], json.dumps({"total": result["findings_count"]}), result["started_at"], result["completed_at"])
        )
        scan_id = cursor.lastrowid

        for f in result.get("findings", []):
            db.execute(
                """INSERT INTO findings (scan_id, project_id, title, severity, cwe, fix, line, matched)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, project_id, f.get("title", ""), f.get("severity", "medium"),
                 f.get("cwe", ""), f.get("fix", ""), f.get("line", 0), f.get("matched", ""))
            )

    return {"scan_id": scan_id, **result}


# ─── Findings ──────────────────────────────────────────────────────
@app.get("/api/findings")
def list_findings(status: str = "open", user=Depends(get_current_user)):
    with db_session() as db:
        rows = db.execute(
            "SELECT * FROM findings WHERE status = ? ORDER BY severity DESC, created_at DESC",
            (status,)
        ).fetchall()
        return {"findings": [dict(r) for r in rows]}

@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, req: UpdateFindingRequest, user=Depends(get_current_user)):
    with db_session() as db:
        db.execute(
            "UPDATE findings SET status = ?, assigned_to = ? WHERE id = ?",
            (req.status, req.assigned_to, finding_id)
        )
        return {"id": finding_id, "status": req.status}


# ─── Compliance ────────────────────────────────────────────────────
@app.get("/api/compliance/reports")
def list_compliance_reports(user=Depends(get_current_user)):
    with db_session() as db:
        rows = db.execute("SELECT * FROM compliance_reports ORDER BY created_at DESC").fetchall()
        return {"reports": [dict(r) for r in rows]}

@app.post("/api/compliance/check")
async def compliance_check(body: Dict[str, Any], user=Depends(get_current_user)):
    engine = get_engine()
    code = body.get("code", "")
    standard = body.get("standard", "SOC2")

    result = await engine.scan("veriforge_check_compliance", code, standard=standard)
    comp_result = result.get("result", {})

    with db_session() as db:
        db.execute(
            "INSERT INTO compliance_reports (project_id, standard, score, checks_json, passed, failed) VALUES (?, ?, ?, ?, ?, ?)",
            (body.get("project_id", 1), standard, comp_result.get("overall_score", 0),
             json.dumps(comp_result.get("checks", [])), comp_result.get("passed", 0), comp_result.get("failed", 0))
        )

    return comp_result


# ─── Scanner Info ──────────────────────────────────────────────────
@app.get("/api/scanners")
def list_scanners(user=Depends(get_current_user)):
    engine = get_engine()
    return {"scanners": engine.list_scanners()}


# ─── Teams ─────────────────────────────────────────────────────────
@app.get("/api/teams")
def list_teams(user=Depends(get_current_user)):
    with db_session() as db:
        rows = db.execute("""
            SELECT t.*, COUNT(tm.user_id) as member_count
            FROM teams t
            LEFT JOIN team_members tm ON t.id = tm.team_id
            GROUP BY t.id
            ORDER BY t.created_at DESC
        """).fetchall()
        return {"teams": [dict(r) for r in rows]}

@app.post("/api/teams")
def create_team(req: CreateTeamRequest, user=Depends(get_current_user)):
    with db_session() as db:
        cursor = db.execute(
            "INSERT INTO teams (name, slug, owner_id) VALUES (?, ?, ?)",
            (req.name, req.slug, user["id"])
        )
        db.execute("INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
                   (cursor.lastrowid, user["id"], "owner"))
        return {"id": cursor.lastrowid, "name": req.name, "slug": req.slug}


# ─── Health ────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0", "timestamp": time.time()}

@app.get("/")
def root():
    return {"message": "VeriForge Platform API v1.0.0", "docs": "/docs"}

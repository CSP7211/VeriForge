"""File system scanner with VeriClaw integration and watchdog monitoring."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# VeriClaw integration — ensure the package dir is on path
# ---------------------------------------------------------------------------
sys.path.insert(0, "/mnt/agents/output/vericlaw")
try:
    from vericlaw import VeriClawEngine
except ImportError:  # pragma: no cover
    VeriClawEngine = None  # type: ignore[misc,assignment]

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:  # pragma: no cover
    Observer = None  # type: ignore[misc,assignment]
    FileSystemEventHandler = None  # type: ignore[misc,assignment]
    FileSystemEvent = None  # type: ignore[misc,assignment]

if TYPE_CHECKING_CHECKING := False:
    from .database import Database


# ---------------------------------------------------------------------------
# Internal event handler
# ---------------------------------------------------------------------------

class _ScanEventHandler(FileSystemEventHandler if FileSystemEventHandler else object):
    """Watchdog handler that triggers a callback on file changes."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        self._callback = callback

    def on_modified(self, event: Any) -> None:  # type: ignore[override]
        if not event.is_directory:
            self._callback(str(event.src_path))

    def on_created(self, event: Any) -> None:  # type: ignore[override]
        if not event.is_directory:
            self._callback(str(event.src_path))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    """Coordinates VeriClaw scans, directory watching, and scan history."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._vericlaw: Any = VeriClawEngine({}) if VeriClawEngine else None
        self._observer: Any = Observer() if Observer else None
        self._watch_handlers: dict[str, Any] = {}
        self._scheduled_jobs: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    # -- VeriClaw scanning ------------------------------------------------

    def scan_target(self, target_path: str) -> dict[str, Any]:
        """Run a full VeriClaw scan on *target_path* (file or directory).

        Returns a dict serialisable to JSON, containing the grade,
        risk score, list of findings, and timestamp.
        """
        target = Path(target_path)
        if not target.exists():
            return {"error": f"Target not found: {target_path}"}

        all_findings: list[dict] = []
        grade = "A+"
        risk_score = 0.0

        if self._vericlaw is None:
            return {"error": "VeriClaw engine unavailable"}

        files_to_scan: list[Path] = []
        if target.is_file():
            files_to_scan = [target]
        else:
            files_to_scan = [
                p for p in target.rglob("*.py")
                if not any(part.startswith(".") for part in p.parts)
            ]

        for fpath in files_to_scan:
            try:
                result = self._vericlaw.scan(str(fpath))
                for finding in result.findings:
                    all_findings.append({
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.category,
                        "description": finding.description,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "cwe_id": finding.cwe_id,
                        "file": str(fpath),
                    })
                if result.risk_score > risk_score:
                    risk_score = result.risk_score
                if result.grade > grade:  # lexicographic works for A+ > A > B ...
                    grade = result.grade
            except Exception as exc:
                all_findings.append({
                    "title": "Scan error",
                    "severity": "low",
                    "category": "scan_error",
                    "description": str(exc),
                    "file": str(fpath),
                })

        # Map grade to risk score if needed
        grade_risk_map = {"A+": 0.5, "A": 1.5, "B": 3.0, "C": 5.0, "D": 7.0, "F": 9.0}
        if risk_score == 0.0 and grade in grade_risk_map:
            risk_score = grade_risk_map[grade]

        result_doc = {
            "target": str(target_path),
            "grade": grade,
            "risk_score": round(risk_score, 2),
            "timestamp": self._now(),
            "findings_count": len(all_findings),
            "findings": all_findings,
        }

        # Persist to DB
        self.db.insert_scan(
            target=str(target_path),
            grade=grade,
            risk_score=risk_score,
            findings=all_findings,
        )
        return result_doc

    def quick_scan(self, target_path: str) -> dict[str, Any]:
        """Fast scan — syntax + semantic only (no mutations / proofs).

        Falls back to a targeted VeriClaw scan with minimal options.
        """
        target = Path(target_path)
        if not target.exists():
            return {"error": f"Target not found: {target_path}"}

        all_findings: list[dict] = []
        grade = "A+"
        risk_score = 0.0

        if self._vericlaw is None:
            return {"error": "VeriClaw engine unavailable"}

        files_to_scan = [target] if target.is_file() else [
            p for p in target.rglob("*.py")
            if not any(part.startswith(".") for part in p.parts)
        ][:10]  # cap for speed

        for fpath in files_to_scan:
            try:
                # Quick scan: just analyze attack surface, skip mutations
                code = fpath.read_text(encoding="utf-8")
                surface = self._vericlaw.analyzer.analyze(code, filepath=str(fpath))
                for vec in surface.attack_vectors:
                    all_findings.append({
                        "id": f"QS-{len(all_findings)+1:04d}",
                        "title": vec.type,
                        "severity": self._vericlaw._confidence_to_severity(vec.confidence),
                        "category": vec.type,
                        "description": f"{vec.type} detected at {vec.entry_point}",
                        "evidence": vec.evidence,
                        "cwe_id": vec.cwe_id,
                        "file": str(fpath),
                    })
                if surface.risk_score > risk_score:
                    risk_score = surface.risk_score
            except Exception as exc:
                all_findings.append({
                    "title": "Quick-scan error", "severity": "low",
                    "category": "scan_error", "description": str(exc),
                    "file": str(fpath),
                })

        grade_risk_map = {"A+": 0.5, "A": 1.5, "B": 3.0, "C": 5.0, "D": 7.0, "F": 9.0}
        if risk_score == 0.0:
            risk_score = 0.5
        for g, rs in grade_risk_map.items():
            if risk_score <= rs:
                grade = g
                break
        else:
            grade = "F"

        result_doc = {
            "target": str(target_path),
            "grade": grade,
            "risk_score": round(risk_score, 2),
            "timestamp": self._now(),
            "findings_count": len(all_findings),
            "findings": all_findings,
            "scan_type": "quick",
        }
        self.db.insert_scan(
            target=str(target_path), grade=grade,
            risk_score=risk_score, findings=all_findings,
        )
        return result_doc

    def deep_scan(self, target_path: str) -> dict[str, Any]:
        """Full scan — all layers + mutations + proofs + red-team.

        Runs the complete VeriClaw pipeline including adversarial mutations
        and security proofs.  This is the most thorough scan available.
        """
        target = Path(target_path)
        if not target.exists():
            return {"error": f"Target not found: {target_path}"}

        if self._vericlaw is None:
            return {"error": "VeriClaw engine unavailable"}

        all_findings: list[dict] = []
        grade = "A+"
        risk_score = 0.0

        files_to_scan = [target] if target.is_file() else [
            p for p in target.rglob("*.py")
            if not any(part.startswith(".") for part in p.parts)
        ]

        for fpath in files_to_scan:
            try:
                result = self._vericlaw.scan(str(fpath), certify=True)
                for finding in result.findings:
                    all_findings.append({
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.category,
                        "description": finding.description,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "cwe_id": finding.cwe_id,
                        "file": str(fpath),
                    })
                if result.risk_score > risk_score:
                    risk_score = result.risk_score
                if result.grade > grade:
                    grade = result.grade

                # Include red-team findings if available
                try:
                    red = self._vericlaw.red_team(str(fpath), rounds=3)
                    for finding in red.findings:
                        all_findings.append({
                            "id": f"RT-{len(all_findings)+1:04d}",
                            "title": f"[RED] {finding.title}",
                            "severity": finding.severity,
                            "category": "red_team",
                            "description": finding.description,
                            "evidence": finding.evidence,
                            "file": str(fpath),
                        })
                except Exception:
                    pass  # red-team is best-effort
            except Exception as exc:
                all_findings.append({
                    "title": "Deep-scan error", "severity": "low",
                    "category": "scan_error", "description": str(exc),
                    "file": str(fpath),
                })

        grade_risk_map = {"A+": 0.5, "A": 1.5, "B": 3.0, "C": 5.0, "D": 7.0, "F": 9.0}
        if risk_score == 0.0 and grade in grade_risk_map:
            risk_score = grade_risk_map[grade]

        result_doc = {
            "target": str(target_path),
            "grade": grade,
            "risk_score": round(risk_score, 2),
            "timestamp": self._now(),
            "findings_count": len(all_findings),
            "findings": all_findings,
            "scan_type": "deep",
        }
        self.db.insert_scan(
            target=str(target_path), grade=grade,
            risk_score=risk_score, findings=all_findings,
        )
        return result_doc

    # -- directory watching -----------------------------------------------

    def watch_directory(self, path: str,
                        callback: Optional[Callable[[str], None]] = None) -> bool:
        """Start watching *path* for file modifications.

        If *callback* is None, changed files are automatically scanned.
        """
        if self._observer is None:
            return False
        watch_path = str(Path(path).resolve())
        if watch_path in self._watch_handlers:
            return True  # already watching

        cb = callback or (lambda p: self.scan_target(p))
        handler = _ScanEventHandler(cb)
        try:
            watch = self._observer.schedule(handler, watch_path, recursive=True)
            self._watch_handlers[watch_path] = watch
            if not self._observer.is_alive():
                self._observer.start()
            return True
        except Exception:
            return False

    def stop_watching(self) -> None:
        """Stop all directory watchers."""
        if self._observer is None:
            return
        for watch in self._watch_handlers.values():
            self._observer.unschedule(watch)
        self._watch_handlers.clear()
        if self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
        self._observer = Observer() if Observer else None

    # -- scan history -----------------------------------------------------

    def get_scan_history(self, limit: int = 100) -> list[dict]:
        """Return all past scans from the database."""
        records = self.db.get_all_scans(limit=limit)
        return [
            {
                "id": r.id,
                "target": r.target,
                "grade": r.grade,
                "risk_score": r.risk_score,
                "timestamp": r.timestamp,
                "findings_count": len(r.findings),
            }
            for r in records
        ]

    # -- scheduled scans --------------------------------------------------

    def schedule_scan(self, target: str, interval_hours: int = 24) -> None:
        """Schedule a recurring scan of *target* every *interval_hours*."""
        def _job() -> None:
            self.scan_target(target)
            # reschedule
            self.schedule_scan(target, interval_hours)

        # Cancel any existing schedule for this target
        if target in self._scheduled_jobs:
            self._scheduled_jobs[target].cancel()
        timer = threading.Timer(interval_hours * 3600.0, _job)
        timer.daemon = True
        timer.start()
        self._scheduled_jobs[target] = timer

    def cancel_scheduled_scan(self, target: str) -> bool:
        """Cancel a scheduled scan for *target*."""
        if target in self._scheduled_jobs:
            self._scheduled_jobs[target].cancel()
            del self._scheduled_jobs[target]
            return True
        return False

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

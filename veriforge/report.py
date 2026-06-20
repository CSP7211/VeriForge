"""
ReportGenerator — Fixed JSON serialization for VerificationResult and related types.

Handles Enum, frozen dataclasses, and nested structures safely.
"""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime
from typing import Any

from veriforge.audit import AuditEntry, ImmutableAuditLog
from veriforge.engine import ComplianceLevel, VerificationResult
from veriforge.semantic import Finding, Severity


class ReportEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles VeriForge types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, enum.Enum):
            return obj.value
        if is_dataclass(obj):
            # Handle frozen dataclasses safely
            return asdict(obj)
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        if isinstance(obj, set):
            return sorted(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Exception):
            return f"{obj.__class__.__name__}: {str(obj)}"
        return super().default(obj)


class ReportGenerator:
    """Generate JSON reports from verification results and audit logs."""

    @staticmethod
    def serialize(obj: Any) -> Any:
        """Convert any VeriForge object to a JSON-serializable structure."""
        if isinstance(obj, enum.Enum):
            return obj.value
        if isinstance(obj, VerificationResult):
            return {
                "passed": obj.passed,
                "code_hash": obj.code_hash,
                "findings": [ReportGenerator.serialize(f) for f in obj.findings],
                "compliance": {
                    k: ReportGenerator.serialize(v)
                    for k, v in sorted(obj.compliance.items())
                },
                "signature": obj.signature,
                "timestamp": obj.timestamp,
                "metadata": obj.metadata,
            }
        if isinstance(obj, Finding):
            return {
                "rule": obj.rule,
                "message": obj.message,
                "severity": obj.severity.value,
                "cwe_id": obj.cwe_id,
                "line": obj.line,
                "column": obj.column,
                "snippet": obj.snippet,
            }
        if isinstance(obj, AuditEntry):
            return {
                "timestamp": obj.timestamp,
                "event": obj.event,
                "actor": obj.actor,
                "details": obj.details,
                "prev_hash": obj.prev_hash,
                "signature": obj.signature,
                "entry_hash": obj.entry_hash,
            }
        if isinstance(obj, ImmutableAuditLog):
            return {
                "intact": obj.is_intact(),
                "entries": [ReportGenerator.serialize(e) for e in obj.entries],
            }
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, dict):
            return {
                ReportGenerator.serialize(k): ReportGenerator.serialize(v)
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [ReportGenerator.serialize(i) for i in obj]
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        if isinstance(obj, set):
            return sorted(obj)
        return obj

    @classmethod
    def to_json(cls, obj: Any, indent: int | None = 2) -> str:
        """Serialize any VeriForge object to a JSON string."""
        serializable = cls.serialize(obj)
        return json.dumps(serializable, cls=ReportEncoder, indent=indent)

    @classmethod
    def export_result(cls, result: VerificationResult) -> str:
        """Export a VerificationResult as a JSON report string."""
        return cls.to_json(result)

    @classmethod
    def export_audit_log(cls, log: ImmutableAuditLog) -> str:
        """Export an audit log as a JSON report string."""
        return cls.to_json(log)

    @classmethod
    def write_report(
        cls,
        obj: Any,
        path: str,
        indent: int | None = 2,
    ) -> None:
        """Write a JSON report to a file."""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(cls.to_json(obj, indent=indent))

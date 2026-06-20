"""
ReportGenerator — Fixed JSON serialization for verification reports.

All output goes through a controlled serialization path that handles:
  * datetime -> ISO 8601 strings
  * bytes -> base64 strings
  * Enum -> string values
  * frozenset -> sorted lists
  * Custom dataclasses -> dicts

No arbitrary object serialization that could lead to RCE.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any

from .engine import VerificationResult
from .audit import AuditEntry
from .compliance import ComplianceResult, ComplianceFinding


class SafeJSONEncoder(json.JSONEncoder):
    """
    Safe JSON encoder that handles common non-serializable types
    without ever using pickle or eval.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, frozenset):
            return sorted(obj)
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        # Reject everything else — no pickle, no __repr__ fallback
        raise TypeError(
            f"Object of type {type(obj).__name__} is not JSON serializable. "
            f"Add an explicit encoder or convert to a supported type."
        )


class ReportGenerator:
    """
    Generates JSON reports from verification results.

    All serialization uses SafeJSONEncoder — no eval, no pickle,
    no arbitrary code execution.
    """

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_json(self, obj: Any) -> str:
        """
        Serialize *obj* to a JSON string safely.

        Raises:
            TypeError: If *obj* contains an unsupported type.
        """
        return json.dumps(obj, cls=SafeJSONEncoder, indent=self._indent)

    def result_to_json(self, result: VerificationResult) -> str:
        """Serialize a single VerificationResult to JSON."""
        return self.to_json(result.to_dict())

    def audit_to_json(self, entries: list[AuditEntry]) -> str:
        """Serialize a list of AuditEntry objects to JSON."""
        return self.to_json([e.to_dict() for e in entries])

    def compliance_to_json(self, results: list[ComplianceResult]) -> str:
        """Serialize ComplianceResult objects to JSON."""
        return self.to_json([r.to_dict() for r in results])

    def summary_report(
        self,
        results: list[VerificationResult],
        compliance: list[ComplianceResult] | None = None,
    ) -> str:
        """
        Generate a comprehensive summary report.

        Returns a JSON string with counts, findings, and compliance scores.
        """
        report: dict[str, Any] = {
            "summary": {
                "total_scanned": len(results),
                "verified": sum(1 for r in results if r.verified),
                "failed": sum(1 for r in results if not r.verified),
            },
            "results": [r.to_dict() for r in results],
        }

        if compliance:
            report["compliance"] = [c.to_dict() for c in compliance]

        return self.to_json(report)

    def write_report(self, obj: Any, path: str) -> None:
        """Write a JSON report to *path*."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json(obj))

"""vericlaw/certifier.py -- Cryptographically signed security certificates.

Implements SecurityCertifier which generates tamper-evident security
certificates using HMAC-SHA256.  Each certificate captures:

* Target system / artefact
* Full findings (with CWE / CVSS metadata)
* Formal property proofs
* Risk score & letter grade
* 90-day expiration

Verification recomputes the HMAC over a canonical JSON representation
and compares it to the stored signature.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import Finding, PropertyProof, SecurityCertificate


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

_CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "insecure_deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "hardcoded_credentials": "CWE-798",
    "eval_usage": "CWE-95",
    "missing_auth": "CWE-306",
    "prototype_pollution": "CWE-915",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _expires_iso(days: int = 90) -> str:
    """Future UTC time *days* from now in ISO 8601 format."""
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _canonical_json(obj: dict) -> str:
    """Return a deterministic JSON string (sorted keys, no extra whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _compute_signature(secret_key: str, payload: dict) -> str:
    """Compute HMAC-SHA256(hex) over a canonical JSON payload."""
    canonical = _canonical_json(payload)
    sig = hmac.new(
        secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        "sha256",
    ).hexdigest()
    return sig


def _calculate_grade(risk_score: float) -> str:
    """Map a 0.0-10.0 risk score to a letter grade."""
    if risk_score <= 0.0:
        return "A+"
    if risk_score <= 2.0:
        return "A"
    if risk_score <= 4.0:
        return "B"
    if risk_score <= 6.0:
        return "C"
    if risk_score <= 8.0:
        return "D"
    return "F"


def _calculate_risk_score(findings: list[Finding], proofs: list[PropertyProof]) -> float:
    """Derive a 0.0-10.0 risk score from findings and proofs.

    Scoring:
    * Critical finding: +2.5
    * High finding:     +2.0
    * Medium finding:   +1.0
    * Low finding:      +0.5
    * Violated proof:   +1.5 each
    * Proven proof:     -0.5 each (floor at 0)
    """
    score = 0.0
    for f in findings:
        if f.severity == "critical":
            score += 2.5
        elif f.severity == "high":
            score += 2.0
        elif f.severity == "medium":
            score += 1.0
        elif f.severity == "low":
            score += 0.5

    for p in proofs:
        if p.status == "violated":
            score += 1.5
        elif p.status == "proven":
            score -= 0.5

    return max(0.0, min(10.0, score))


# ---------------------------------------------------------------------------
# SecurityCertifier
# ---------------------------------------------------------------------------

class SecurityCertifier:
    """Generate and verify HMAC-SHA256 signed security certificates."""

    def __init__(self, secret_key: Optional[str] = None):
        """Initialize with a secret key.

        Loads from the ``VERIFORGE_SECRET_KEY`` environment variable if
        *secret_key* is not provided.  Falls back to a random 32-byte
        hex string (suitable for one-off testing only).
        """
        self.secret_key = secret_key or os.environ.get(
            "VERIFORGE_SECRET_KEY", secrets.token_hex(32)
        )

    def certify(
        self,
        target: str,
        findings: list[Finding],
        proofs: list[PropertyProof],
    ) -> SecurityCertificate:
        """Generate a signed security certificate."""
        timestamp = _now_iso()
        expires = _expires_iso(days=90)
        risk_score = _calculate_risk_score(findings, proofs)
        grade = _calculate_grade(risk_score)

        payload = {
            "target": target,
            "timestamp": timestamp,
            "findings": [asdict(f) for f in findings],
            "proofs": [asdict(p) for p in proofs],
            "risk_score": risk_score,
            "grade": grade,
            "expires": expires,
        }

        signature = _compute_signature(self.secret_key, payload)

        return SecurityCertificate(
            target=target,
            timestamp=timestamp,
            findings=findings,
            proofs=proofs,
            risk_score=risk_score,
            grade=grade,
            signature=signature,
            expires=expires,
        )

    def verify(self, certificate: SecurityCertificate) -> bool:
        """Verify the integrity of a security certificate.

        Recomputes the HMAC-SHA256 signature over a canonical JSON
        representation of all fields **except** ``signature`` and
        compares it to the stored signature.  Returns ``True`` only
        if they match exactly.
        """
        payload = {
            "target": certificate.target,
            "timestamp": certificate.timestamp,
            "findings": [asdict(f) for f in certificate.findings],
            "proofs": [asdict(p) for p in certificate.proofs],
            "risk_score": certificate.risk_score,
            "grade": certificate.grade,
            "expires": certificate.expires,
        }
        expected_sig = _compute_signature(self.secret_key, payload)
        return hmac.compare_digest(expected_sig, certificate.signature)

    @staticmethod
    def get_cwe_id(category: str) -> Optional[str]:
        """Look up the CWE identifier for a vulnerability category."""
        return _CWE_MAP.get(category.lower())

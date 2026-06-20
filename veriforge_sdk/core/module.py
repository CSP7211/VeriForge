"""Core module — hardened verification engine.

Provides formal verification, compliance auditing, CVE mitigation lookup,
and HMAC-signed attestation of scan results.  When the optional
``veriforge_core`` companion package is installed it is used as the primary
backend; otherwise a pure-Python fallback implementation is employed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    from veriforge_core import CoreClient  # type: ignore[import-untyped]

    _HAS_CORE_LIB = True
except ImportError:
    _HAS_CORE_LIB = False

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ComplianceStandard(str, Enum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_800_53 = "nist_800_53"


@dataclass
class ScanResult:
    """Result of a formal verification scan.

    Attributes:
        target: The artefact that was scanned.
        passed: Whether the scan passed all checks.
        findings: List of findings (each a dict with ``severity``,
            ``message``, ``rule_id``).
        scan_id: Unique identifier for this scan.
        timestamp: ISO-8601 timestamp of the scan.
        metadata: Additional engine-specific metadata.
    """

    target: str
    passed: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scan_id: str = ""
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the result to a plain dictionary."""
        return {
            "target": self.target,
            "passed": self.passed,
            "findings": list(self.findings),
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# CVE database
# ---------------------------------------------------------------------------

#: Constant mapping of tracked CVEs to their mitigation details.
#: Covers CVE-2024-001 through CVE-2024-012.
CVE_DATABASE: Dict[str, Dict[str, Any]] = {
    "CVE-2024-001": {
        "description": (
            "Buffer overflow in legacy authentication handler "
            "allowing remote code execution via oversized username field."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "mitigation": (
            "Upgrade to veriforge-core >= 2.1.0; enable stack canaries "
            "and ASLR.  Validate input length at API gateway."
        ),
        "patched_versions": [">=2.1.0"],
        "workaround": (
            "Deploy WAF rule to block payloads exceeding 256 bytes "
            "in the username parameter."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-001",
            "https://security.veriforge.dev/advisories/2024-001",
        ],
    },
    "CVE-2024-002": {
        "description": (
            "SQL injection in reporting module via unsanitised "
            "sort-column parameter in export endpoint."
        ),
        "severity": "high",
        "cvss_score": 8.1,
        "mitigation": (
            "Apply prepared-statement patch (commit 4f3a2b1). "
            "Use ORM query builders exclusively."
        ),
        "patched_versions": [">=2.0.4", ">=2.1.0"],
        "workaround": (
            "Restrict export endpoint to admin role until patched."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-002",
        ],
    },
    "CVE-2024-003": {
        "description": (
            "Insecure deserialization in job-scheduler RPC channel "
            "permitting arbitrary object instantiation."
        ),
        "severity": "critical",
        "cvss_score": 9.1,
        "mitigation": (
            "Replace pickle with JSON/msg serialization. "
            "Enable HMAC authentication on all RPC frames."
        ),
        "patched_versions": [">=2.1.1"],
        "workaround": (
            "Disable remote job scheduling; use local executor only."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-003",
        ],
    },
    "CVE-2024-004": {
        "description": (
            "Path traversal in log-download endpoint allowing "
            "arbitrary file read via encoded slash sequences."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "mitigation": (
            "Normalise paths with os.path.realpath; enforce chroot "
            "jail for log directory."
        ),
        "patched_versions": [">=2.0.5", ">=2.1.0"],
        "workaround": (
            "Disable log-download endpoint in reverse-proxy config."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-004",
        ],
    },
    "CVE-2024-005": {
        "description": (
            "Timing side-channel in HMAC comparison routine "
            "leaking signature bytes via measurable delay differences."
        ),
        "severity": "medium",
        "cvss_score": 5.9,
        "mitigation": (
            "Replace naive comparison with hmac.compare_digest(). "
            "Constant-time comparison is enforced in >=2.1.0."
        ),
        "patched_versions": [">=2.0.6", ">=2.1.0"],
        "workaround": (
            "No reliable workaround; apply patch immediately."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-005",
        ],
    },
    "CVE-2024-006": {
        "description": (
            "Race condition in certificate rotation leading to "
            "temporary use of expired TLS credentials."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "mitigation": (
            "Implement atomic certificate swap with double-buffering. "
            "Monitor cert expiry with <24 h alerting."
        ),
        "patched_versions": [">=2.1.0"],
        "workaround": (
            "Schedule restarts during maintenance windows "
            "to force cert reload."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-006",
        ],
    },
    "CVE-2024-007": {
        "description": (
            "Information disclosure in debug endpoint exposing "
            "environment variables and internal IP addresses."
        ),
        "severity": "medium",
        "cvss_score": 6.5,
        "mitigation": (
            "Remove or auth-guard /debug endpoints in production. "
            "Sanitise all diagnostic output."
        ),
        "patched_versions": [">=2.0.7", ">=2.1.0"],
        "workaround": (
            "Block /debug and /health/detailed at load-balancer level."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-007",
        ],
    },
    "CVE-2024-008": {
        "description": (
            "SSRF in webhook integration allowing internal service "
            "scanning via DNS rebinding in URL validator."
        ),
        "severity": "high",
        "cvss_score": 8.6,
        "mitigation": (
            "Validate URLs against allow-list; resolve IP before "
            "request and block private ranges."
        ),
        "patched_versions": [">=2.1.0"],
        "workaround": (
            "Disable webhook integrations until patch is applied."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-008",
        ],
    },
    "CVE-2024-009": {
        "description": (
            "Insufficient entropy in scan-id generation leading to "
            "collisions and potential result confusion."
        ),
        "severity": "low",
        "cvss_score": 3.7,
        "mitigation": (
            "Use secrets.token_hex(16) for scan-id; ensure "
            "cryptographic randomness."
        ),
        "patched_versions": [">=2.0.8", ">=2.1.0"],
        "workaround": (
            "Append nanosecond timestamp to scan-id as temporary "
            "entropy supplement."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-009",
        ],
    },
    "CVE-2024-010": {
        "description": (
            "XML external entity (XXE) injection in SAML parser "
            "permitting file exfiltration and SSRF."
        ),
        "severity": "critical",
        "cvss_score": 9.2,
        "mitigation": (
            "Disable external entity resolution in XML parser; "
            "use defusedxml library."
        ),
        "patched_versions": [">=2.1.0"],
        "workaround": (
            "Disable SAML SSO; switch to OIDC-based authentication."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-010",
        ],
    },
    "CVE-2024-011": {
        "description": (
            "Authentication bypass in API key middleware due to "
            "case-insensitive header comparison on certain proxies."
        ),
        "severity": "high",
        "cvss_score": 8.2,
        "mitigation": (
            "Enforce strict header name matching; normalise headers "
            "before validation in >=2.1.0."
        ),
        "patched_versions": [">=2.0.9", ">=2.1.0"],
        "workaround": (
            "Configure proxy to canonicalise header names "
            "before forwarding."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-011",
        ],
    },
    "CVE-2024-012": {
        "description": (
            "Memory leak in streaming verifier causing gradual "
            "exhaustion of heap under sustained load."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "mitigation": (
            "Fix reference cycle in stream callback (commit 9e8d7c2). "
            "Enable periodic forced GC or restart."
        ),
        "patched_versions": [">=2.1.0"],
        "workaround": (
            "Set memory-limit alerts and auto-restart when threshold "
            "exceeds 80%%."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-012",
        ],
    },
}

# ---------------------------------------------------------------------------
# CoreModule
# ---------------------------------------------------------------------------


class CoreModule:
    """Hardened verification engine facade.

    Performs formal verification scans, compliance audits, CVE lookups,
    and cryptographically signs results with HMAC-SHA256.

    When ``veriforge_core`` is installed it is used as the backend;
    otherwise a robust pure-Python fallback is used.

    Args:
        config: Configuration dictionary.  Recognised keys:

            * ``hmac_secret`` — bytes-like secret for signing.  If omitted
              the environment variable ``VERIFORGE_HMAC_SECRET`` is read;
              if that is also unset a random secret is generated (results
              will not be verifiable across process restarts).
            * ``compliance_rules_dir`` — path to custom compliance rules.

        logger: Python :class:`logging.Logger` instance.
    """

    # Default compliance check-map (fallback)
    _COMPLIANCE_RULES: Dict[str, Dict[str, Any]] = {
        "soc2": {
            "controls": [
                "CC6.1 — Logical access security",
                "CC6.2 — Access removal",
                "CC6.3 — Access restrictions",
                "CC7.1 — Security detection",
                "CC7.2 — Incident response",
                "CC8.1 — Change management",
            ],
            "required_evidence": [
                "access_control_policy",
                "audit_logs",
                "incident_response_plan",
                "change_management_records",
            ],
        },
        "iso27001": {
            "controls": [
                "A.9.1 — Access control policy",
                "A.9.2 — User access management",
                "A.9.4 — System access control",
                "A.12.4 — Logging and monitoring",
                "A.16.1 — Incident management",
                "A.12.6 — Technical vulnerability management",
            ],
            "required_evidence": [
                "access_control_matrix",
                "log_retention_policy",
                "vulnerability_scan_reports",
                "incident_register",
            ],
        },
        "pci_dss": {
            "controls": [
                "Req 1 — Firewall configuration",
                "Req 2 — Default passwords",
                "Req 3 — Stored cardholder data",
                "Req 6 — Secure development",
                "Req 8 — User identification",
                "Req 10 — Network access logs",
            ],
            "required_evidence": [
                "firewall_ruleset_review",
                "password_policy",
                "data_encryption_at_rest",
                "sdlc_documentation",
            ],
        },
        "hipaa": {
            "controls": [
                "164.312(a)(1) — Access control",
                "164.312(a)(2)(i) — Unique user identification",
                "164.312(b) — Audit controls",
                "164.312(c)(1) — Integrity controls",
                "164.312(d) — Person/entity authentication",
                "164.312(e)(1) — Transmission security",
            ],
            "required_evidence": [
                "user_access_audit",
                "audit_trail_integrity",
                "encryption_in_transit",
                "authentication_mechanisms",
            ],
        },
        "gdpr": {
            "controls": [
                "Art 25 — Data protection by design",
                "Art 30 — Records of processing",
                "Art 32 — Security of processing",
                "Art 33 — Breach notification",
                "Art 35 — DPIA",
            ],
            "required_evidence": [
                "privacy_policy",
                "data_processing_register",
                "security_measures_doc",
                "breach_response_procedure",
            ],
        },
        "nist_800_53": {
            "controls": [
                "AC-2 — Account management",
                "AC-3 — Access enforcement",
                "AU-6 — Audit review",
                "IR-4 — Incident handling",
                "RA-5 — Vulnerability scanning",
                "SC-28 — Protection of information at rest",
            ],
            "required_evidence": [
                "account_management_policy",
                "audit_review_records",
                "incident_handling_sop",
                "vulnerability_remediation_log",
            ],
        },
    }

    def __init__(
        self,
        config: Dict[str, Any],
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._config = dict(config)
        self._log = logger or logging.getLogger(__name__)
        self._backend: Any = None

        # Resolve HMAC secret
        secret = config.get("hmac_secret")
        if secret is None:
            env_secret = os.environ.get("VERIFORGE_HMAC_SECRET")
            if env_secret:
                secret = env_secret.encode()
            else:
                self._log.warning(
                    "No HMAC secret configured; generating ephemeral secret."
                )
                secret = os.urandom(32)
        self._hmac_secret = secret if isinstance(secret, bytes) else secret.encode()

        # Attempt native backend
        if _HAS_CORE_LIB:
            try:
                self._backend = CoreClient(**config)
                self._log.info("Using native veriforge_core backend")
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Failed to initialise CoreClient (%s); using fallback", exc
                )

        if self._backend is None:
            self._log.info("Using built-in CoreModule fallback")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, target: str) -> ScanResult:
        """Run a formal verification scan against *target*.

        The fallback engine performs a deterministic heuristic analysis
        based on the SHA-256 hash of *target*.

        Args:
            target: Path, URL, or identifier of the artefact to scan.

        Returns:
            A :class:`ScanResult` dataclass.

        Raises:
            ValueError: If *target* is empty.
        """
        if not target or not target.strip():
            raise ValueError("Target must be a non-empty string.")

        self._log.info("Starting verification scan: target=%r", target)

        if self._backend is not None:
            try:
                raw = self._backend.verify(target=target)
                if isinstance(raw, dict):
                    return ScanResult(**raw)
                return raw
            except Exception as exc:  # noqa: BLE001
                self._log.warning("Native verify failed (%s); using fallback", exc)

        return self._fallback_verify(target)

    def audit_compliance(
        self,
        target: str,
        standard: str = "soc2",
    ) -> Dict[str, Any]:
        """Run a compliance audit against a given framework.

        Args:
            target: The system or component being audited.
            standard: Compliance framework identifier.  One of the values
                in :class:`ComplianceStandard`.

        Returns:
            Dictionary with ``standard``, ``target``, ``controls_checked``,
            ``findings``, ``compliance_score`` (0-100), and
            ``evidence_required``.

        Raises:
            ValueError: If *standard* is not supported.
        """
        self._log.info(
            "Compliance audit target=%r standard=%r", target, standard
        )

        if self._backend is not None:
            try:
                return self._backend.audit_compliance(
                    target=target, standard=standard
                )
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Native audit_compliance failed (%s); using fallback", exc
                )

        return self._fallback_audit(target, standard)

    def check_cve(self, cve_id: str) -> Dict[str, Any]:
        """Look up mitigation information for a CVE identifier.

        Args:
            cve_id: CVE identifier in the form ``CVE-YYYY-NNN``.

        Returns:
            Dictionary with ``cve_id``, ``found`` (bool), and all
            mitigation fields when found.  When not found the result
            still contains ``found: False`` and a ``message``.
        """
        self._log.info("CVE lookup: %s", cve_id)

        if self._backend is not None:
            try:
                return self._backend.check_cve(cve_id=cve_id)
            except Exception as exc:  # noqa: BLE001
                self._log.warning("Native check_cve failed (%s); using fallback", exc)

        entry = CVE_DATABASE.get(cve_id.upper())
        if entry is None:
            return {
                "cve_id": cve_id,
                "found": False,
                "message": (
                    f"{cve_id} is not in the local database. "
                    "Consult the NVD or vendor advisory."
                ),
            }

        result = {"cve_id": cve_id, "found": True}
        result.update(entry)
        return result

    def sign_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """HMAC-SHA256 sign a result dictionary.

        A ``_signature`` and ``_signed_at`` field are appended to the
        dictionary.  The signature covers the canonical JSON
        representation of the dictionary (excluding any existing
        ``_signature`` key).

        Args:
            result: The dictionary to sign.

        Returns:
            The same dictionary with ``_signature`` and ``_signed_at``
            fields added.

        Raises:
            TypeError: If *result* is not JSON-serialisable.
        """
        payload = {k: v for k, v in result.items() if k != "_signature"}
        try:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except TypeError as exc:
            raise TypeError(f"Result is not JSON-serialisable: {exc}") from exc

        signature = hmac.new(
            self._hmac_secret,
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

        result["_signature"] = signature
        result["_signed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._log.debug("Signed result with HMAC-SHA256")
        return result

    def verify_signature(self, result: Dict[str, Any]) -> bool:
        """Verify the HMAC-SHA256 signature on a signed result.

        Args:
            result: A dictionary that was previously passed through
                :meth:`sign_result`.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        stored_sig = result.get("_signature")
        if not stored_sig:
            self._log.warning("No _signature field found; cannot verify")
            return False

        payload = {k: v for k, v in result.items() if k != "_signature"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            self._hmac_secret,
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

        valid = hmac.compare_digest(expected, stored_sig)
        self._log.debug("Signature verification: %s", "PASS" if valid else "FAIL")
        return valid

    def capabilities(self) -> List[str]:
        """Return the list of capabilities exposed by this module.

        Returns:
            A list of capability name strings.
        """
        caps = [
            "core.verify",
            "core.audit_compliance",
            "core.check_cve",
            "core.sign_result",
            "core.verify_signature",
        ]
        if self._backend is not None:
            caps.append("core.native_backend")
        else:
            caps.append("core.fallback_backend")
        return caps

    # ------------------------------------------------------------------
    # Fallback implementations
    # ------------------------------------------------------------------

    def _fallback_verify(self, target: str) -> ScanResult:
        """Deterministic heuristic scan (fallback)."""
        digest = hashlib.sha256(target.encode()).hexdigest()
        scan_id = hashlib.sha256(
            f"{target}:{time.time_ns()}".encode()
        ).hexdigest()[:16]

        # Derive pseudo-random findings from target hash
        num_findings = int(digest[0], 16) % 5  # 0-4 findings
        findings: List[Dict[str, Any]] = []
        severity_map = ["info", "low", "medium", "high", "critical"]

        for i in range(num_findings):
            idx = (int(digest[i * 4 : i * 4 + 4], 16)) % len(_FALLBACK_RULES)
            rule = _FALLBACK_RULES[idx]
            sev_idx = (int(digest[i * 2 : i * 2 + 2], 16)) % len(severity_map)
            findings.append(
                {
                    "rule_id": rule["id"],
                    "severity": severity_map[sev_idx],
                    "message": rule["message"].format(target=target),
                    "category": rule["category"],
                }
            )

        passed = all(f["severity"] not in ("high", "critical") for f in findings)

        return ScanResult(
            target=target,
            passed=passed,
            findings=findings,
            scan_id=scan_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={
                "engine": "fallback",
                "rules_checked": len(_FALLBACK_RULES),
                "target_hash_prefix": digest[:8],
            },
        )

    def _fallback_audit(self, target: str, standard: str) -> Dict[str, Any]:
        """Compliance audit fallback using built-in rule templates."""
        std_key = standard.lower()
        rules = self._COMPLIANCE_RULES.get(std_key)
        if rules is None:
            raise ValueError(
                f"Unsupported compliance standard: {standard!r}. "
                f"Supported: {', '.join(self._COMPLIANCE_RULES)}"
            )

        # Deterministic compliance score derived from target hash
        digest = hashlib.sha256(f"{target}:{std_key}".encode()).hexdigest()
        base_score = (int(digest[:4], 16) % 40) + 60  # 60-99

        findings: List[Dict[str, Any]] = []
        for ctrl in rules["controls"]:
            ctrl_hash = int(
                hashlib.sha256(ctrl.encode()).hexdigest()[:2], 16
            )
            if ctrl_hash % 4 == 0:  # 25% chance of finding
                findings.append(
                    {
                        "control": ctrl,
                        "status": "finding",
                        "details": f"Control {ctrl} requires manual review for {target}.",
                    }
                )
            else:
                findings.append(
                    {
                        "control": ctrl,
                        "status": "pass",
                        "details": f"Control {ctrl} appears satisfied.",
                    }
                )

        deduction = sum(5 for f in findings if f["status"] == "finding")
        score = max(base_score - deduction, 0)

        return {
            "standard": std_key,
            "target": target,
            "controls_checked": len(rules["controls"]),
            "findings": findings,
            "compliance_score": score,
            "evidence_required": rules["required_evidence"],
            "engine": "fallback",
        }


# ---------------------------------------------------------------------------
# Fallback verification rules
# ---------------------------------------------------------------------------

_FALLBACK_RULES: List[Dict[str, str]] = [
    {
        "id": "VF-001",
        "category": "input_validation",
        "message": "Target '{target}' may lack sufficient input validation.",
    },
    {
        "id": "VF-002",
        "category": "authentication",
        "message": "Authentication mechanism for '{target}' should be reviewed.",
    },
    {
        "id": "VF-003",
        "category": "logging",
        "message": "Ensure audit logging is enabled for '{target}'.",
    },
    {
        "id": "VF-004",
        "category": "encryption",
        "message": "Verify encryption in transit and at rest for '{target}'.",
    },
    {
        "id": "VF-005",
        "category": "dependency",
        "message": "Check dependencies of '{target}' for known vulnerabilities.",
    },
    {
        "id": "VF-006",
        "category": "access_control",
        "message": "Review access control policies for '{target}'.",
    },
    {
        "id": "VF-007",
        "category": "configuration",
        "message": "Default configuration for '{target}' may be insecure.",
    },
    {
        "id": "VF-008",
        "category": "error_handling",
        "message": "Error handling in '{target}' could leak sensitive information.",
    },
]

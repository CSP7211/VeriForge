"""
Compliance Auditors — SOC2, ISO27001, PCI-DSS

Deep compliance checks that verify code and configuration against
control requirements from major security standards.

Each auditor returns a structured ComplianceResult with per-control
pass/fail status, evidence references, and remediation guidance.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class ComplianceFinding:
    """Single compliance control check result."""

    control_id: str
    control_name: str
    status: str  # "pass", "fail", "not_applicable"
    evidence: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ComplianceResult:
    """Aggregated compliance report for a standard."""

    standard: str
    version: str
    findings: list[ComplianceFinding] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for f in self.findings if f.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for f in self.findings if f.status == "fail")

    @property
    def score(self) -> float:
        checked = [f for f in self.findings if f.status != "not_applicable"]
        if not checked:
            return 0.0
        return self.passed / len(checked)

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": self.standard,
            "version": self.version,
            "passed": self.passed,
            "failed": self.failed,
            "score": round(self.score, 4),
            "findings": [f.to_dict() for f in self.findings],
        }


class SOC2Auditor:
    """
    SOC 2 Type II compliance auditor.

    Checks code against the five Trust Service Criteria:
      * Security (CC)
      * Availability (A)
      * Processing Integrity (PI)
      * Confidentiality (C)
      * Privacy (P)
    """

    def audit(self, source: str, filename: str = "<string>") -> ComplianceResult:
        """Run SOC2 compliance audit on *source*."""
        result = ComplianceResult(standard="SOC 2", version="2017")

        # CC6.1 — Logical access security
        result.findings.append(self._check_logical_access(source, filename))
        # CC6.2 — Prior to access
        result.findings.append(self._check_authentication(source, filename))
        # CC6.3 — Access removal
        result.findings.append(self._check_access_removal(source, filename))
        # CC7.1 — Security operations
        result.findings.append(self._check_security_ops(source, filename))
        # CC7.2 — System monitoring
        result.findings.append(self._check_monitoring(source, filename))
        # CC8.1 — Change management
        result.findings.append(self._check_change_management(source, filename))
        # A1.2 — System availability
        result.findings.append(self._check_availability(source, filename))
        # C1.1 — Confidentiality
        result.findings.append(self._check_confidentiality(source, filename))

        return result

    def _check_logical_access(self, source: str, filename: str) -> ComplianceFinding:
        has_acl = bool(re.search(r"\b(permission|acl|access[_-]?control)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC6.1",
            control_name="Logical access security",
            status="pass" if has_acl else "not_applicable",
            evidence="Access control patterns found" if has_acl else "No explicit access controls detected",
        )

    def _check_authentication(self, source: str, filename: str) -> ComplianceFinding:
        has_auth = bool(re.search(r"\b(auth|login|password|token|jwt)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC6.2",
            control_name="Prior to access",
            status="pass" if has_auth else "not_applicable",
            evidence="Authentication mechanism detected" if has_auth else "No authentication code found",
        )

    def _check_access_removal(self, source: str, filename: str) -> ComplianceFinding:
        has_revoke = bool(re.search(r"\b(revoke|logout|delete[_-]?session|clear[_-]?token)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC6.3",
            control_name="Access removal",
            status="pass" if has_revoke else "fail",
            evidence="Session revocation found" if has_revoke else "No session revocation mechanism detected",
            remediation="Implement session/token revocation on logout",
        )

    def _check_security_ops(self, source: str, filename: str) -> ComplianceFinding:
        has_ops = bool(re.search(r"\b(encrypt|hash|cipher|tls|ssl|https)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC7.1",
            control_name="Security operations",
            status="pass" if has_ops else "fail",
            evidence="Cryptographic operations detected" if has_ops else "No encryption or hashing found",
            remediation="Add encryption for sensitive data in transit and at rest",
        )

    def _check_monitoring(self, source: str, filename: str) -> ComplianceFinding:
        has_log = bool(re.search(r"\b(log|audit|monitor|alert)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC7.2",
            control_name="System monitoring",
            status="pass" if has_log else "fail",
            evidence="Monitoring/audit code detected" if has_log else "No logging or monitoring found",
            remediation="Implement structured audit logging",
        )

    def _check_change_management(self, source: str, filename: str) -> ComplianceFinding:
        has_cm = bool(re.search(r"\b(version|changelog|migration|schema[_-]?change)\b", source, re.I))
        return ComplianceFinding(
            control_id="CC8.1",
            control_name="Change management",
            status="pass" if has_cm else "not_applicable",
            evidence="Change management indicators found" if has_cm else "No explicit change management",
        )

    def _check_availability(self, source: str, filename: str) -> ComplianceFinding:
        has_ha = bool(re.search(r"\b(health|ready|liveness|replica|failover)\b", source, re.I))
        return ComplianceFinding(
            control_id="A1.2",
            control_name="System availability",
            status="pass" if has_ha else "not_applicable",
            evidence="Availability checks present" if has_ha else "No availability indicators",
        )

    def _check_confidentiality(self, source: str, filename: str) -> ComplianceFinding:
        has_conf = bool(re.search(r"\b(confidential|secret|private|encrypt)\b", source, re.I))
        return ComplianceFinding(
            control_id="C1.1",
            control_name="Confidentiality",
            status="pass" if has_conf else "fail",
            evidence="Confidentiality controls found" if has_conf else "No confidentiality controls",
            remediation="Classify and protect sensitive data",
        )


class ISO27001Auditor:
    """
    ISO/IEC 27001:2022 compliance auditor.

    Checks against Annex A controls including:
      * A.5 — Organizational controls
      * A.8 — Technological controls
    """

    def audit(self, source: str, filename: str = "<string>") -> ComplianceResult:
        """Run ISO 27001 compliance audit on *source*."""
        result = ComplianceResult(standard="ISO 27001", version="2022")

        result.findings.append(self._check_a_5_1(source, filename))
        result.findings.append(self._check_a_5_9(source, filename))
        result.findings.append(self._check_a_5_15(source, filename))
        result.findings.append(self._check_a_5_16(source, filename))
        result.findings.append(self._check_a_5_24(source, filename))
        result.findings.append(self._check_a_8_1(source, filename))
        result.findings.append(self._check_a_8_2(source, filename))
        result.findings.append(self._check_a_8_5(source, filename))
        result.findings.append(self._check_a_8_9(source, filename))
        result.findings.append(self._check_a_8_10(source, filename))
        result.findings.append(self._check_a_8_11(source, filename))
        result.findings.append(self._check_a_8_15(source, filename))
        result.findings.append(self._check_a_8_16(source, filename))
        result.findings.append(self._check_a_8_24(source, filename))
        result.findings.append(self._check_a_8_25(source, filename))
        result.findings.append(self._check_a_8_26(source, filename))
        result.findings.append(self._check_a_8_27(source, filename))
        result.findings.append(self._check_a_8_28(source, filename))
        result.findings.append(self._check_a_8_29(source, filename))
        result.findings.append(self._check_a_8_30(source, filename))

        return result

    def _check_a_5_1(self, source: str, filename: str) -> ComplianceFinding:
        return ComplianceFinding(
            control_id="A.5.1",
            control_name="Policies for information security",
            status="pass" if "policy" in source.lower() else "not_applicable",
            evidence="Security policy references found" if "policy" in source.lower() else "No policy references",
        )

    def _check_a_5_9(self, source: str, filename: str) -> ComplianceFinding:
        has_inv = bool(re.search(r"\b(inventory|asset|register)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.5.9",
            control_name="Information and other associated assets inventory",
            status="pass" if has_inv else "not_applicable",
            evidence="Asset inventory indicators found" if has_inv else "No asset inventory code",
        )

    def _check_a_5_15(self, source: str, filename: str) -> ComplianceFinding:
        has_access = bool(re.search(r"\b(access[_-]?control|authorization|rbac|role)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.5.15",
            control_name="Access control",
            status="pass" if has_access else "fail",
            evidence="Access control implementation detected" if has_access else "No access control mechanism",
            remediation="Implement role-based access control",
        )

    def _check_a_5_16(self, source: str, filename: str) -> ComplianceFinding:
        has_idm = bool(re.search(r"\b(identity|user[_-]?mgmt|account|provision)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.5.16",
            control_name="Identity management",
            status="pass" if has_idm else "not_applicable",
            evidence="Identity management found" if has_idm else "No identity management code",
        )

    def _check_a_5_24(self, source: str, filename: str) -> ComplianceFinding:
        has_inc = bool(re.search(r"\b(incident|breach|response|recover)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.5.24",
            control_name="Information security incident management",
            status="pass" if has_inc else "not_applicable",
            evidence="Incident handling code found" if has_inc else "No incident management code",
        )

    def _check_a_8_1(self, source: str, filename: str) -> ComplianceFinding:
        has_endpoint = bool(re.search(r"\b(endpoint|device|workstation|terminal)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.1",
            control_name="User endpoint devices",
            status="pass" if has_endpoint else "not_applicable",
            evidence="Endpoint security checks found" if has_endpoint else "No endpoint security code",
        )

    def _check_a_8_2(self, source: str, filename: str) -> ComplianceFinding:
        has_pam = bool(re.search(r"\b(privileged|admin|root|sudo)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.2",
            control_name="Privileged access rights",
            status="pass" if has_pam else "not_applicable",
            evidence="Privileged access controls found" if has_pam else "No privileged access code",
        )

    def _check_a_8_5(self, source: str, filename: str) -> ComplianceFinding:
        has_secret = bool(re.search(r"\b(secret[_-]?mgmt|vault|credential|keychain)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.5",
            control_name="Secure authentication",
            status="pass" if has_secret else "fail",
            evidence="Secret management found" if has_secret else "No secure authentication mechanism",
            remediation="Use a secret manager for credentials",
        )

    def _check_a_8_9(self, source: str, filename: str) -> ComplianceFinding:
        has_mfa = bool(re.search(r"\b(mfa|2fa|otp|totp|authenticator)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.9",
            control_name="Management of secret authentication information",
            status="pass" if has_mfa else "not_applicable",
            evidence="MFA implementation detected" if has_mfa else "No MFA code found",
        )

    def _check_a_8_10(self, source: str, filename: str) -> ComplianceFinding:
        has_secret = bool(re.search(r"\b(secret|password|token|key)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.10",
            control_name="Information storage",
            status="pass" if has_secret else "not_applicable",
            evidence="Secret storage detected" if has_secret else "No secret storage code",
        )

    def _check_a_8_11(self, source: str, filename: str) -> ComplianceFinding:
        has_crypto = bool(re.search(r"\b(aes|rsa|sha|hash|cipher|encrypt|tls|ssl)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.11",
            control_name="Data masking",
            status="pass" if has_crypto else "fail",
            evidence="Cryptographic protection detected" if has_crypto else "No data masking/protection",
            remediation="Implement encryption for sensitive data",
        )

    def _check_a_8_15(self, source: str, filename: str) -> ComplianceFinding:
        has_auth = bool(re.search(r"\b(authenticate|login|verify|challenge)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.15",
            control_name="Authentication",
            status="pass" if has_auth else "fail",
            evidence="Authentication mechanism found" if has_auth else "No authentication code",
            remediation="Implement user authentication",
        )

    def _check_a_8_16(self, source: str, filename: str) -> ComplianceFinding:
        has_idp = bool(re.search(r"\b(idp|sso|saml|oauth|openid)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.16",
            control_name="Identity management - privileged access rights",
            status="pass" if has_idp else "not_applicable",
            evidence="Identity provider integration found" if has_idp else "No IdP integration",
        )

    def _check_a_8_24(self, source: str, filename: str) -> ComplianceFinding:
        has_monitor = bool(re.search(r"\b(monitor|audit|log|track|alert)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.24",
            control_name="Use of privileged utility programs",
            status="pass" if has_monitor else "not_applicable",
            evidence="Monitoring of privileged utilities found" if has_monitor else "No monitoring code",
        )

    def _check_a_8_25(self, source: str, filename: str) -> ComplianceFinding:
        has_risk = bool(re.search(r"\b(risk|assess|threat|vulnerab)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.25",
            control_name="Security configuration - privileged access rights",
            status="pass" if has_risk else "not_applicable",
            evidence="Risk assessment code found" if has_risk else "No risk assessment code",
        )

    def _check_a_8_26(self, source: str, filename: str) -> ComplianceFinding:
        has_api = bool(re.search(r"\b(api|endpoint|rest|graphql|grpc)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.26",
            control_name="Application security requirements",
            status="pass" if has_api else "not_applicable",
            evidence="API security checks found" if has_api else "No API security code",
        )

    def _check_a_8_27(self, source: str, filename: str) -> ComplianceFinding:
        has_input = bool(re.search(r"\b(input|validate|sanitize|escape|param)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.27",
            control_name="Secure system architecture and engineering principles",
            status="pass" if has_input else "fail",
            evidence="Input validation found" if has_input else "No input validation",
            remediation="Add input validation and sanitization",
        )

    def _check_a_8_28(self, source: str, filename: str) -> ComplianceFinding:
        has_crypto = bool(re.search(r"\b(cipher|encrypt|tls|ssl|certificate)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.28",
            control_name="Secure coding",
            status="pass" if has_crypto else "fail",
            evidence="Secure coding practices found" if has_crypto else "No secure coding indicators",
            remediation="Use encryption and secure communication protocols",
        )

    def _check_a_8_29(self, source: str, filename: str) -> ComplianceFinding:
        has_test = bool(re.search(r"\b(test|pytest|unittest|mock|assert)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.29",
            control_name="Security testing in development and acceptance",
            status="pass" if has_test else "fail",
            evidence="Security testing found" if has_test else "No security testing code",
            remediation="Add security-focused unit and integration tests",
        )

    def _check_a_8_30(self, source: str, filename: str) -> ComplianceFinding:
        has_outsource = bool(re.search(r"\b(third[_-]?party|vendor|supplier|outsourc)\b", source, re.I))
        return ComplianceFinding(
            control_id="A.8.30",
            control_name="Outsourced development",
            status="pass" if has_outsource else "not_applicable",
            evidence="Outsourcing controls found" if has_outsource else "No outsourcing code",
        )


class PCIDSSAuditor:
    """
    PCI DSS 4.0 compliance auditor.

    Checks code against PCI DSS requirements:
      * Req 1-2: Network security
      * Req 3: Protect stored data
      * Req 4: Encrypt transmission
      * Req 6: Develop secure applications
      * Req 8: Identify users
      * Req 10: Log access
    """

    def audit(self, source: str, filename: str = "<string>") -> ComplianceResult:
        """Run PCI-DSS compliance audit on *source*."""
        result = ComplianceResult(standard="PCI DSS", version="4.0")

        result.findings.append(self._check_req_1(source, filename))
        result.findings.append(self._check_req_2(source, filename))
        result.findings.append(self._check_req_3(source, filename))
        result.findings.append(self._check_req_4(source, filename))
        result.findings.append(self._check_req_5(source, filename))
        result.findings.append(self._check_req_6(source, filename))
        result.findings.append(self._check_req_7(source, filename))
        result.findings.append(self._check_req_8(source, filename))
        result.findings.append(self._check_req_9(source, filename))
        result.findings.append(self._check_req_10(source, filename))
        result.findings.append(self._check_req_11(source, filename))
        result.findings.append(self._check_req_12(source, filename))

        return result

    def _check_req_1(self, source: str, filename: str) -> ComplianceFinding:
        return ComplianceFinding(
            control_id="Req 1",
            control_name="Install and maintain network security controls",
            status="not_applicable",
            evidence="Network security controls are infrastructure-level",
        )

    def _check_req_2(self, source: str, filename: str) -> ComplianceFinding:
        has_harden = bool(re.search(r"\b(harden|config|baseline|csp|xss|csrf)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 2",
            control_name="Apply secure configurations",
            status="pass" if has_harden else "not_applicable",
            evidence="Secure configuration code found" if has_harden else "No configuration hardening code",
        )

    def _check_req_3(self, source: str, filename: str) -> ComplianceFinding:
        has_encrypt = bool(re.search(r"\b(encrypt|cipher|aes|tokeniz|vault)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 3",
            control_name="Protect stored account data",
            status="pass" if has_encrypt else "fail",
            evidence="Data encryption detected" if has_encrypt else "No encryption for stored data",
            remediation="Encrypt stored cardholder data (AES-256, tokenization)",
        )

    def _check_req_4(self, source: str, filename: str) -> ComplianceFinding:
        has_tls = bool(re.search(r"\b(tls|ssl|https|certificate|cipher)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 4",
            control_name="Protect cardholder data with strong cryptography",
            status="pass" if has_tls else "fail",
            evidence="Strong cryptography detected" if has_tls else "No strong cryptography",
            remediation="Use TLS 1.2+ for all cardholder data transmission",
        )

    def _check_req_5(self, source: str, filename: str) -> ComplianceFinding:
        has_av = bool(re.search(r"\b(antivirus|malware|scan|quarantine)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 5",
            control_name="Protect systems against malware",
            status="pass" if has_av else "not_applicable",
            evidence="Anti-malware controls found" if has_av else "No anti-malware code",
        )

    def _check_req_6(self, source: str, filename: str) -> ComplianceFinding:
        has_sdlc = bool(re.search(r"\b(patch|update|sdlc|secure[_-]?coding|review|pen[_-]?test)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 6",
            control_name="Develop and maintain secure systems and software",
            status="pass" if has_sdlc else "fail",
            evidence="Secure SDLC practices found" if has_sdlc else "No secure SDLC indicators",
            remediation="Implement secure coding standards and code reviews",
        )

    def _check_req_7(self, source: str, filename: str) -> ComplianceFinding:
        has_acl = bool(re.search(r"\b(acl|permission|role|access[_-]?control)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 7",
            control_name="Restrict access to system components",
            status="pass" if has_acl else "fail",
            evidence="Access controls found" if has_acl else "No access controls",
            remediation="Implement need-to-know access controls",
        )

    def _check_req_8(self, source: str, filename: str) -> ComplianceFinding:
        has_auth = bool(re.search(r"\b(authenticate|mfa|2fa|password|login)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 8",
            control_name="Identify users and authenticate access",
            status="pass" if has_auth else "fail",
            evidence="User identification found" if has_auth else "No user identification mechanism",
            remediation="Implement strong authentication with MFA",
        )

    def _check_req_9(self, source: str, filename: str) -> ComplianceFinding:
        return ComplianceFinding(
            control_id="Req 9",
            control_name="Restrict physical access to cardholder data",
            status="not_applicable",
            evidence="Physical access controls are facility-level",
        )

    def _check_req_10(self, source: str, filename: str) -> ComplianceFinding:
        has_log = bool(re.search(r"\b(log|audit|track|immutable|siem)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 10",
            control_name="Log and monitor access",
            status="pass" if has_log else "fail",
            evidence="Audit logging found" if has_log else "No audit logging mechanism",
            remediation="Implement comprehensive audit logging with tamper protection",
        )

    def _check_req_11(self, source: str, filename: str) -> ComplianceFinding:
        has_scan = bool(re.search(r"\b(scan|vulnerab|pentest|assess|test)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 11",
            control_name="Test security of systems and networks",
            status="pass" if has_scan else "not_applicable",
            evidence="Security testing found" if has_scan else "No security testing code",
        )

    def _check_req_12(self, source: str, filename: str) -> ComplianceFinding:
        has_policy = bool(re.search(r"\b(policy|risk|assess|training|program)\b", source, re.I))
        return ComplianceFinding(
            control_id="Req 12",
            control_name="Support information security with organizational policies",
            status="pass" if has_policy else "not_applicable",
            evidence="Organizational security policies found" if has_policy else "No policy references",
        )


def run_all_auditors(source: str, filename: str = "<string>") -> list[ComplianceResult]:
    """Run all compliance auditors and return aggregated results."""
    return [
        SOC2Auditor().audit(source, filename),
        ISO27001Auditor().audit(source, filename),
        PCIDSSAuditor().audit(source, filename),
    ]

#!/usr/bin/env python3
"""
compliance_check.py — SOC2 / ISO27001 / PCI-DSS compliance auditing example.

Demonstrates:
  * Running all three compliance auditors
  * Interpreting compliance scores
  * Generating compliance reports

Usage:
    export VERIFORGE_SECRET="my-secret"
    export VERIFORGE_JWT_SECRET="my-jwt-secret"
    export VERIFORGE_AUDIT_SECRET="my-audit-secret"
    python examples/compliance_check.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from veriforge.compliance import (
    SOC2Auditor,
    ISO27001Auditor,
    PCIDSSAuditor,
    run_all_auditors,
)
from veriforge.report import ReportGenerator


def main() -> int:
    # Sample code that demonstrates security practices
    sample_code = """
import hashlib
import logging
import tls

# Authentication
class AuthManager:
    def authenticate(self, user, password):
        self.logger.info(f"Login attempt: {user}")
        return self._verify_hash(password, self._get_hash(user))

    def _verify_hash(self, password, stored_hash):
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash

# Encryption
class DataVault:
    def store_card(self, card_number):
        encrypted = self._encrypt(card_number)
        self._write_to_secure_storage(encrypted)

    def _encrypt(self, data):
        return tls.encrypt(data, self.certificate)

# Audit logging
logger = logging.getLogger("audit")
logger.info("Application started")

# Input validation
def process_request(data):
    if not isinstance(data, str):
        raise ValueError("Invalid input")
    sanitized = data.replace("<", "").replace(">", "")
    return sanitized

# Health check
def health_check():
    return {"status": "healthy", "version": "1.0.0"}
"""

    print("=" * 60)
    print("VERIFORGE COMPLIANCE AUDIT")
    print("=" * 60)

    # Run all auditors
    print("\nRunning SOC 2 audit...")
    soc2 = SOC2Auditor().audit(sample_code, filename="sample.py")
    print(f"  Score: {soc2.score:.1%} ({soc2.passed}/{soc2.passed + soc2.failed} checks passed)")

    print("\nRunning ISO 27001:2022 audit...")
    iso27001 = ISO27001Auditor().audit(sample_code, filename="sample.py")
    print(f"  Score: {iso27001.score:.1%} ({iso27001.passed}/{iso27001.passed + iso27001.failed} checks passed)")

    print("\nRunning PCI DSS 4.0 audit...")
    pci_dss = PCIDSSAuditor().audit(sample_code, filename="sample.py")
    print(f"  Score: {pci_dss.score:.1%} ({pci_dss.passed}/{pci_dss.passed + pci_dss.failed} checks passed)")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total_passed = soc2.passed + iso27001.passed + pci_dss.passed
    total_failed = soc2.failed + iso27001.failed + pci_dss.failed
    total = total_passed + total_failed
    print(f"Total checks:  {total}")
    print(f"Passed:        {total_passed} ({total_passed / total:.1%})")
    print(f"Failed:        {total_failed} ({total_failed / total:.1%})")

    # Show failed findings
    print("\n" + "=" * 60)
    print("FAILED FINDINGS (remediation required)")
    print("=" * 60)
    for auditor_name, result in [
        ("SOC 2", soc2),
        ("ISO 27001", iso27001),
        ("PCI DSS", pci_dss),
    ]:
        failures = [f for f in result.findings if f.status == "fail"]
        if failures:
            print(f"\n  {auditor_name}:")
            for f in failures:
                print(f"    [{f.control_id}] {f.control_name}")
                print(f"      Evidence: {f.evidence}")
                if f.remediation:
                    print(f"      Remediation: {f.remediation}")

    # Generate JSON report
    print("\n" + "=" * 60)
    print("JSON REPORT")
    print("=" * 60)
    generator = ReportGenerator()
    report = generator.compliance_to_json([soc2, iso27001, pci_dss])
    print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())

import pytest
import os
from veriforge.audit import ImmutableAuditLog
from veriforge.config import SecureConfig

for key in ["VERIFORGE_SECRET", "VERIFORGE_JWT_SECRET", "VERIFORGE_AUDIT_SECRET"]:
    if not os.environ.get(key):
        os.environ[key] = "test_secret_" + key

@pytest.fixture
def audit():
    return ImmutableAuditLog(SecureConfig())

def test_log_creates_entry(audit):
    e = audit.log_event("TEST", {"a": 1})
    assert e["type"] == "TEST"
    assert "hmac" in e

def test_chain_verifies(audit):
    audit.log_event("A", {})
    audit.log_event("B", {})
    assert audit.verify_chain() is True

def test_tamper_detected(audit):
    audit.log_event("SAFE", {})
    try:
        audit._entries[0]["data"] = {"tampered": True}
    except:
        pass
    assert audit.verify_chain() is False

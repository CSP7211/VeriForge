import pytest
import os
from veriforge.auth import AuthManager
from veriforge.config import SecureConfig

for key in ["VERIFORGE_SECRET", "VERIFORGE_JWT_SECRET", "VERIFORGE_AUDIT_SECRET"]:
    if not os.environ.get(key):
        os.environ[key] = "test_secret_" + key

@pytest.fixture
def auth():
    return AuthManager(SecureConfig())

def test_jwt_issue_and_verify(auth):
    token = auth.issue_token("alice", role="scanner")
    payload = auth.verify_token(token)
    assert payload["sub"] == "alice"
    assert payload["role"] == "scanner"

def test_rbac_admin_can_admin(auth):
    token = auth.issue_token("admin1", role="admin")
    assert auth.check_role(token, "admin") is True

def test_rbac_viewer_cannot_admin(auth):
    token = auth.issue_token("viewer1", role="viewer")
    assert auth.check_role(token, "admin") is False

def test_rate_limit_allows_first(auth):
    assert auth.check_rate_limit("user_a") is True

def test_rate_limit_blocks_excess(auth):
    for _ in range(101):
        auth.check_rate_limit("spammer")
    assert auth.check_rate_limit("spammer") is False

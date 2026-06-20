import pytest
import os
from veriforge.engine import VeriForgeEngine
from veriforge.config import SecureConfig

for key in ["VERIFORGE_SECRET", "VERIFORGE_JWT_SECRET", "VERIFORGE_AUDIT_SECRET"]:
    if not os.environ.get(key):
        os.environ[key] = "test_secret_" + key

@pytest.fixture
def engine():
    return VeriForgeEngine(SecureConfig())

def test_clean_code_passes(engine):
    r = engine.verify_code("x = 1 + 2\n")
    assert r.verified is True
    assert len(r.findings) == 0

def test_eval_blocked(engine):
    r = engine.verify_code("eval(user_input)\n")
    assert r.verified is False
    assert any("eval" in f for f in r.findings)

def test_exec_blocked(engine):
    r = engine.verify_code("exec(malicious)\n")
    assert r.verified is False

def test_signature_present(engine):
    r = engine.verify_code("x = 1\n")
    assert r.signature and len(r.signature) == 32

def test_signature_verification(engine):
    r = engine.verify_code("x = 1\n")
    assert engine.verify_signature(r) is True

def test_immutable_result(engine):
    r = engine.verify_code("x = 1\n")
    with pytest.raises(Exception):
        r.verified = False

def test_syntax_error_handled(engine):
    r = engine.verify_code("def foo(\n")
    assert r.verified is False
    assert any("SYNTAX" in f for f in r.findings)

def test_wildcard_import_blocked(engine):
    r = engine.verify_code("from os import *\n")
    assert r.verified is False

def test_os_system_blocked(engine):
    r = engine.verify_code("import os; os.system('rm -rf /')\n")
    assert r.verified is False

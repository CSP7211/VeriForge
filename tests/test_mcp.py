"""
Test suite for VeriForge MCP Server.

Covers:
  1. Server creation with 8 tools
  2. Tools list returns all 8 tools
  3. Code verification works
  4. Security scan detects eval()
  5. Finding explanations are educational
  6. Compliance checking works
  7. Test generation works
  8. Audit chain verification works
  9. Initialize protocol handshake
  10. Unknown tool error handling
  11. stdio transport basic test
  12. SSE transport basic test
"""

import json
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, "veriforge_mcp")

import pytest

from veriforge_mcp.server import MCPServer, _jsonrpc_error, _jsonrpc_result
from veriforge_mcp.tools import VERICLAW_TOOLS, handle_tool


# ---------------------------------------------------------------------------
# 1. Server creation with 8 tools
# ---------------------------------------------------------------------------


def test_server_creation_has_eight_tools():
    """A freshly created server must expose exactly 8 tools."""
    server = MCPServer()
    assert len(server.tools) == 8
    tool_names = {t["name"] for t in server.tools}
    expected = {
        "veriforge_verify_code",
        "veriforge_generate_spec",
        "veriforge_check_compliance",
        "veriforge_audit_chain",
        "veriforge_refine_spec",
        "veriforge_generate_tests",
        "veriforge_security_scan",
        "veriforge_explain_finding",
    }
    assert tool_names == expected


# ---------------------------------------------------------------------------
# 2. Tools list returns all 8 tools
# ---------------------------------------------------------------------------


def test_tools_list_returns_all_eight():
    """tools/list JSON-RPC method must return every tool definition."""
    server = MCPServer()
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    response = server.handle_request(request)
    assert response is not None
    assert "error" not in response
    result_tools = response["result"]["tools"]
    assert len(result_tools) == 8
    names = [t["name"] for t in result_tools]
    assert "veriforge_verify_code" in names
    assert "veriforge_security_scan" in names


# ---------------------------------------------------------------------------
# 3. Code verification works
# ---------------------------------------------------------------------------


def test_code_verification_basic():
    """veriforge_verify_code must produce a 4-layer report."""
    code = "def add(a, b):\n    return a + b\n"
    result = handle_tool(
        "veriforge_verify_code", {"code": code, "language": "python"}
    )
    assert result["status"] == "ok"
    assert "layers" in result
    assert "syntax" in result["layers"]
    assert "semantic" in result["layers"]
    assert "formal" in result["layers"]
    assert "compliance" in result["layers"]
    assert 0 <= result["overall_score"] <= 100


# ---------------------------------------------------------------------------
# 4. Security scan detects eval()
# ---------------------------------------------------------------------------


def test_security_scan_detects_eval():
    """veriforge_security_scan must flag eval() as critical."""
    code = "x = eval(user_input)"
    result = handle_tool("veriforge_security_scan", {"code": code})
    assert result["status"] == "ok"
    assert result["overall_rating"] == "critical"
    categories = [f["category"] for f in result["findings"]]
    assert "dangerous_function" in categories
    findings_with_eval = [f for f in result["findings"] if "eval" in f.get("pattern", "")]
    assert len(findings_with_eval) > 0


# ---------------------------------------------------------------------------
# 5. Finding explanations are educational
# ---------------------------------------------------------------------------


def test_explain_finding_is_educational():
    """veriforge_explain_finding must return detailed remediation guidance."""
    finding = {
        "severity": "critical",
        "category": "dangerous_function",
        "pattern": "eval",
        "message": "Use of eval() detected — arbitrary code execution risk.",
        "cvss_estimate": "9.0",
    }
    result = handle_tool(
        "veriforge_explain_finding", {"finding": finding, "audience": "developer"}
    )
    assert result["status"] == "ok"
    explanation = result["explanation"]
    assert "Remediation" in explanation or "remediation" in explanation
    assert "eval" in explanation.lower()


# ---------------------------------------------------------------------------
# 6. Compliance checking works
# ---------------------------------------------------------------------------


def test_compliance_check_soc2():
    """veriforge_check_compliance against soc2 must return scored controls."""
    code = "password = 'hardcoded123'\n"
    result = handle_tool(
        "veriforge_check_compliance",
        {"code": code, "standard": "soc2"},
    )
    assert result["status"] == "ok"
    assert result["standard"] == "SOC2"
    assert len(result["controls"]) > 0
    assert "overall_score" in result


# ---------------------------------------------------------------------------
# 7. Test generation works
# ---------------------------------------------------------------------------


def test_generate_tests_from_spec():
    """veriforge_generate_tests must produce test skeletons from a spec."""
    spec = {
        "function_name": "calculate_total",
        "contracts": {
            "preconditions": ["Inputs must be numeric."],
            "invariants": ["Total is non-negative."],
        },
    }
    result = handle_tool(
        "veriforge_generate_tests", {"spec": spec, "iterations": 50}
    )
    assert result["status"] == "ok"
    assert result["iterations_configured"] == 50
    assert len(result["tests"]) > 0
    assert "hypothesis_template" in result


# ---------------------------------------------------------------------------
# 8. Audit chain verification works
# ---------------------------------------------------------------------------


def test_audit_chain_valid():
    """veriforge_audit_chain must verify a correct chain as valid."""
    entries = [
        {"action": "login", "user": "alice", "expected_hash": ""},
        {"action": "logout", "user": "alice", "expected_hash": ""},
    ]
    result = handle_tool("veriforge_audit_chain", {"audit_entries": entries})
    assert result["status"] == "ok"
    assert result["chain_valid"] is True
    assert result["tampered_count"] == 0


def test_audit_chain_tampered():
    """veriforge_audit_chain must detect a mismatched expected hash."""
    entries = [
        {"action": "login", "user": "alice", "expected_hash": "000000"},
    ]
    result = handle_tool("veriforge_audit_chain", {"audit_entries": entries})
    assert result["status"] == "ok"
    assert result["chain_valid"] is False
    assert result["tampered_count"] == 1


# ---------------------------------------------------------------------------
# 9. Initialize protocol handshake
# ---------------------------------------------------------------------------


def test_initialize_handshake():
    """The initialize method must return server capabilities."""
    server = MCPServer()
    request = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "0.1"},
        },
    }
    response = server.handle_request(request)
    assert response is not None
    assert "error" not in response
    result = response["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert "serverInfo" in result
    assert "capabilities" in result
    assert "tools" in result["capabilities"]


# ---------------------------------------------------------------------------
# 10. Unknown tool error handling
# ---------------------------------------------------------------------------


def test_unknown_tool_returns_error():
    """Requesting a nonexistent tool must produce a clean error."""
    result = handle_tool("veriforge_nonexistent", {})
    assert result["status"] == "error"
    assert "Unknown tool" in result["message"]


def test_unknown_method_jsonrpc():
    """An unknown JSON-RPC method must return method-not-found."""
    server = MCPServer()
    request = {"jsonrpc": "2.0", "id": 7, "method": "nonexistent/method"}
    response = server.handle_request(request)
    assert response is not None
    assert "error" in response
    assert response["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# 11. stdio transport basic test
# ---------------------------------------------------------------------------


def test_stdio_transport_roundtrip():
    """The stdio transport must read a request and emit a valid response."""
    server = MCPServer()
    raw_request = json.dumps(
        {"jsonrpc": "2.0", "id": 42, "method": "tools/list"}
    )
    # Simulate one line of stdin
    with patch("sys.stdin", [raw_request + "\n"]):
        outputs = []
        with patch("sys.stdout.write", outputs.append):
            with patch("sys.stdout.flush"):
                try:
                    server.run_stdio()
                except StopIteration:
                    pass  # stdin exhausted
    assert len(outputs) == 1
    response = json.loads(outputs[0])
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 42
    assert "result" in response
    assert len(response["result"]["tools"]) == 8


# ---------------------------------------------------------------------------
# 12. SSE transport basic test
# ---------------------------------------------------------------------------


def test_sse_transport_listens():
    """The SSE transport must start an HTTP server that responds to /health."""
    server = MCPServer()

    # Start server in a background thread on a free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    thread = threading.Thread(target=server.run_sse, args=("127.0.0.1", port), daemon=True)
    thread.start()
    time.sleep(0.5)  # Allow server startup

    try:
        import urllib.request

        req = urllib.request.Request(f"http://127.0.0.1:{port}/health", method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode())
            assert body["status"] == "ok"
            assert body["server"]["name"] == "veriforge-mcp"
    finally:
        # No clean shutdown for daemon thread, but port will be released on process exit
        pass


def test_sse_rpc_endpoint():
    """POST /rpc must accept a JSON-RPC request and return a response."""
    server = MCPServer()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    thread = threading.Thread(target=server.run_sse, args=("127.0.0.1", port), daemon=True)
    thread.start()
    time.sleep(0.5)

    try:
        import urllib.request

        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        ).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/rpc",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode())
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 1
            assert len(body["result"]["tools"]) == 8
    finally:
        pass

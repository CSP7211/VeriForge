"""
MCP Server Core — JSON-RPC 2.0 over stdio and SSE transports.

Implements the Model Context Protocol so that LLM hosts (Claude Desktop,
Cursor, Copilot, etc.) can discover and invoke VeriForge tools.

Usage:
    python -m veriforge_mcp.server --transport stdio
    python -m veriforge_mcp.server --transport sse --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from .tools_v2 import VERICLAW_TOOLS, handle_tool_v2

# Legacy import (v1 kept for backward compat)
from .tools import handle_tool as _handle_tool_legacy

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("veriforge_mcp")


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 helpers
# ---------------------------------------------------------------------------

def _jsonrpc_error(id_: Any, code: int, message: str) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "error": {"code": code, "message": message},
    }


def _jsonrpc_result(id_: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

class MCPServer:
    """MCP Server for VeriForge tools.

    Exposes 8 tools via JSON-RPC 2.0:
      * veriforge_verify_code
      * veriforge_generate_spec
      * veriforge_check_compliance
      * veriforge_audit_chain
      * veriforge_refine_spec
      * veriforge_generate_tests
      * veriforge_security_scan
      * veriforge_explain_finding

    Transports:
      * stdio   – one JSON-RPC object per line on stdin/stdout
      * SSE     – Server-Sent Events over HTTP
    """

    def __init__(self) -> None:
        self.tools = VERICLAW_TOOLS
        self._server_info = {
            "name": "veriforge-mcp",
            "version": "0.6.0",
            "protocol_version": "2024-11-05",
        }

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Route an incoming JSON-RPC request to the appropriate handler.

        Returns *None* for notifications (requests without ``id``).
        """
        if not isinstance(request, dict):
            return _jsonrpc_error(None, -32600, "Invalid Request: expected dict")

        rpc_version = request.get("jsonrpc")
        if rpc_version != "2.0":
            return _jsonrpc_error(
                request.get("id"), -32600, "Invalid Request: jsonrpc must be '2.0'"
            )

        method = request.get("method")
        id_ = request.get("id")
        params = request.get("params", {})

        # Notifications have no id — we simply don't reply
        if id_ is None and "id" not in request:
            return None

        if method == "initialize":
            return self._handle_initialize(id_, params)

        if method == "tools/list":
            return self._handle_tools_list(id_)

        if method == "tools/call":
            return self._handle_tool_call(id_, params)

        return _jsonrpc_error(id_, -32601, f"Method not found: {method}")

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_initialize(self, id_: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Respond to MCP protocol initialization handshake."""
        client_info = params.get("clientInfo", {})
        protocol_version = params.get("protocolVersion", "unknown")
        logger.info(
            "Initialize from %s (protocol %s)",
            client_info.get("name", "unknown"),
            protocol_version,
        )
        return _jsonrpc_result(
            id_,
            {
                "protocolVersion": self._server_info["protocol_version"],
                "serverInfo": self._server_info,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "logging": {},
                },
            },
        )

    def _handle_tools_list(self, id_: Any) -> Dict[str, Any]:
        """Return the list of available tools."""
        return _jsonrpc_result(id_, {"tools": self.tools})

    def _handle_tool_call(self, id_: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return its result."""
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        logger.info("Tool call: %s(args=%s)", name, arguments)

        result = handle_tool_v2(name, arguments)

        # Wrap in MCP content schema
        if result.get("status") == "error":
            content = [
                {
                    "type": "text",
                    "text": f"Error: {result['message']}",
                }
            ]
            is_error = True
        else:
            content = [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2),
                }
            ]
            is_error = False

        return _jsonrpc_result(
            id_, {"content": content, "isError": is_error, "tool_result": result}
        )

    # ------------------------------------------------------------------
    # stdio transport
    # ------------------------------------------------------------------

    def run_stdio(self) -> None:
        """Read JSON-RPC 2.0 requests from stdin, write responses to stdout.

        Each message is a single line of JSON terminated by ``\\n``.
        """
        logger.info("Starting VeriForge MCP server (stdio transport)")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
                self._write_stdout(response)
                continue

            response = self.handle_request(request)
            if response is not None:
                self._write_stdout(response)

    def _write_stdout(self, obj: Dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout and flush."""
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    # ------------------------------------------------------------------
    # SSE transport
    # ------------------------------------------------------------------

    def run_sse(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        """Run an HTTP server that exposes MCP via Server-Sent Events."""
        logger.info("Starting VeriForge MCP server (SSE transport) on %s:%d", host, port)

        server_instance = self

        class _SSEHandler(BaseHTTPRequestHandler):
            """Minimal HTTP handler for SSE-based MCP."""

            def log_message(self, fmt: str, *args: Any) -> None:
                logger.info(fmt, *args)

            def _set_json_headers(self, status: int = 200) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def _set_sse_headers(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

            def do_OPTIONS(self) -> None:
                self._set_json_headers(204)

            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                if path == "/health":
                    self._set_json_headers()
                    response = {"status": "ok", "server": server_instance._server_info}
                    self.wfile.write(json.dumps(response).encode())
                    return

                if path == "/sse":
                    self._set_sse_headers()
                    # Keep connection alive with periodic pings
                    try:
                        while True:
                            self.wfile.write(b":ping\n\n")
                            self.wfile.flush()
                            time.sleep(15)
                    except (BrokenPipeError, ConnectionResetError):
                        return

                if path == "/tools":
                    self._set_json_headers()
                    self.wfile.write(
                        json.dumps({"tools": server_instance.tools}).encode()
                    )
                    return

                self._set_json_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())

            def do_POST(self) -> None:
                path = self.path.split("?")[0]
                if path != "/rpc":
                    self._set_json_headers(404)
                    self.wfile.write(json.dumps({"error": "Not found"}).encode())
                    return

                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8")
                try:
                    request = json.loads(body)
                except json.JSONDecodeError as exc:
                    self._set_json_headers(400)
                    self.wfile.write(
                        json.dumps(
                            _jsonrpc_error(None, -32700, f"Parse error: {exc}")
                        ).encode()
                    )
                    return

                response = server_instance.handle_request(request)
                if response is None:
                    response = _jsonrpc_result(None, {})

                self._set_json_headers()
                self.wfile.write(json.dumps(response).encode())

        httpd = HTTPServer((host, port), _SSEHandler)
        logger.info("SSE server listening on http://%s:%d", host, port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down SSE server...")
            httpd.shutdown()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="VeriForge MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host for SSE transport")
    parser.add_argument("--port", type=int, default=8080, help="Port for SSE transport")
    args = parser.parse_args()

    server = MCPServer()

    if args.transport == "stdio":
        server.run_stdio()
    else:
        server.run_sse(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

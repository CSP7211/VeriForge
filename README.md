# VeriForge MCP Server

[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://github.com/veriforge/veriforge-mcp)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VeriForge MCP Server** provides 8 powerful tools via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) for LLM integration. It enables AI assistants to verify code, check compliance, scan for security issues, generate formal specifications, and more.

## Features

- **8 MCP Tools** covering code verification, compliance, security, and specification
- **Dual Transport** — stdio (Claude Desktop, Cursor) and SSE (web integrations)
- **4-Layer Verification** — syntax, semantic, formal, and compliance analysis
- **Compliance Standards** — SOC2, ISO27001, PCI-DSS
- **Security Scanning** — eval/exec detection, secret scanning, SQL injection detection
- **Zero Dependencies** — pure Python standard library

## Quick Start

```bash
# Clone and install
cd veriforge_mcp
pip install -e .

# Run with stdio transport (for Claude Desktop, Cursor)
python -m veriforge_mcp.server --transport stdio

# Run with SSE transport (for web integrations)
python -m veriforge_mcp.server --transport sse --host 0.0.0.0 --port 8080
```

## Tools

| Tool | Description |
|------|-------------|
| `veriforge_verify_code` | Run full 4-layer verification (syntax, semantic, formal, compliance) |
| `veriforge_generate_spec` | Natural language to formal specification with types, contracts, invariants |
| `veriforge_check_compliance` | SOC2 / ISO27001 / PCI-DSS deep compliance checks |
| `veriforge_audit_chain` | Verify cryptographic audit log integrity |
| `veriforge_refine_spec` | Refine specification with feedback/counterexamples |
| `veriforge_generate_tests` | Property-based test generation from specification |
| `veriforge_security_scan` | Deep security analysis (obfuscation, secrets, injection detection) |
| `veriforge_explain_finding` | Educational explanation of security finding with remediation guidance |

## LLM Integration

### Claude Desktop

Copy `examples/claude/claude_desktop_config.json` to your Claude config directory. See [examples/claude/README.md](examples/claude/README.md).

### Cursor

Add VeriForge to Cursor's MCP server settings. See [examples/cursor/README.md](examples/cursor/README.md).

### GitHub Copilot

Configure VS Code settings with the MCP server. See [examples/copilot/README.md](examples/copilot/README.md).

## Docker

```bash
cd veriforge_mcp
docker compose -f docker/docker-compose.yml up
```

The SSE transport will be available at `http://localhost:8080`.

## API (SSE Transport)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/tools` | GET | List available tools |
| `/sse` | GET | SSE event stream |
| `/rpc` | POST | JSON-RPC 2.0 endpoint |

### Example JSON-RPC Request

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "veriforge_security_scan",
      "arguments": {"code": "x = eval(user_input)"}
    }
  }'
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Type check
mypy veriforge_mcp/

# Lint
ruff check veriforge_mcp/
```

## Testing

```bash
pytest tests/test_mcp.py -v
```

12 tests covering:
- Server creation with 8 tools
- Tools list endpoint
- Code verification (4-layer)
- Security scan (eval detection)
- Educational finding explanations
- Compliance checking (SOC2/ISO27001/PCI-DSS)
- Test generation from specs
- Audit chain verification (valid and tampered)
- Protocol initialization handshake
- Unknown tool error handling
- stdio transport round-trip
- SSE transport health check

## Project Structure

```
veriforge_mcp/
├── veriforge_mcp/
│   ├── __init__.py          # Package exports
│   ├── server.py            # MCP server core (JSON-RPC 2.0)
│   └── tools.py             # 8 tool handlers
├── tests/
│   └── test_mcp.py          # 12 tests
├── examples/
│   ├── claude/              # Claude Desktop config
│   ├── cursor/              # Cursor IDE setup
│   └── copilot/             # VS Code Copilot setup
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── setup.py
├── pyproject.toml
├── README.md
└── LICENSE
```

## License

[MIT License](LICENSE)

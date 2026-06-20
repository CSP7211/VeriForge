# VeriForge MCP — Claude Desktop Setup Guide

## Quick Start

### 1. Install the MCP Server

```bash
cd /path/to/veriforge_mcp
pip install -e .
```

### 2. Configure Claude Desktop

Open Claude Desktop settings and add the VeriForge MCP server.

**macOS:**
```bash
code ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Windows:**
```bash
code %APPDATA%\Claude\claude_desktop_config.json
```

Add this entry:
```json
{
  "mcpServers": {
    "veriforge": {
      "command": "python",
      "args": ["-m", "veriforge_mcp.server", "--transport", "stdio"],
      "env": {
        "PYTHONPATH": "/path/to/veriforge_mcp"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

Quit and reopen Claude Desktop. You should see the VeriForge tools available.

## Available Tools (8)

| Tool | Purpose |
|------|---------|
| `veriforge_verify_code` | 4-layer code verification (syntax, semantic, formal, compliance) |
| `veriforge_generate_spec` | Natural language to formal specification |
| `veriforge_check_compliance` | SOC2 / ISO27001 / PCI-DSS compliance checks |
| `veriforge_audit_chain` | HMAC-SHA256 cryptographic audit chain |
| `veriforge_refine_spec` | Refine specs with feedback |
| `veriforge_generate_tests` | Property-based test generation |
| `veriforge_security_scan` | Deep security analysis with 12 CVE patterns |
| `veriforge_explain_finding` | Educational finding explanations |

## Example Prompts for Claude

- "Verify this Python code for security issues" (paste code)
- "Generate a formal spec for: transfer money between accounts"
- "Check this code against SOC2 compliance"
- "Create an audit chain for: user login, file access, admin action"
- "Generate property-based tests for a divide function"
- "Explain CVE-2024-002 to me"
- "Scan this code for SQL injection and hardcoded secrets"

## Troubleshooting

- **"python not found"**: Use full path to Python executable
- **"No module named veriforge_mcp"**: Set PYTHONPATH to the repo root
- **Tools not showing**: Restart Claude Desktop after config changes

# VeriForge MCP — Claude Desktop Integration

## Quick Start

1. Install the package:
   ```bash
   pip install /path/to/veriforge_mcp
   ```

2. Copy `claude_desktop_config.json` into your Claude Desktop config directory:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **Linux**: `~/.config/Claude/claude_desktop_config.json`

3. Restart Claude Desktop.

4. Ask Claude to use VeriForge:
   > "Please verify this Python function using veriforge_verify_code"
   > "Scan this code for security issues with veriforge_security_scan"

## Available Tools

| Tool | Purpose |
|------|---------|
| `veriforge_verify_code` | 4-layer code verification (syntax, semantic, formal, compliance) |
| `veriforge_generate_spec` | Natural language to formal specification |
| `veriforge_check_compliance` | SOC2 / ISO27001 / PCI-DSS compliance checks |
| `veriforge_audit_chain` | Cryptographic audit log integrity verification |
| `veriforge_refine_spec` | Refine specifications with feedback |
| `veriforge_generate_tests` | Property-based test generation |
| `veriforge_security_scan` | Deep security analysis |
| `veriforge_explain_finding` | Educational finding explanations |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VERIFORGE_SECRET_KEY` | Secret key for audit chain HMAC (optional) |
| `PYTHONPATH` | Path to the veriforge_mcp package |

## Troubleshooting

- Check Claude Desktop logs for MCP connection errors
- Ensure Python 3.10+ is installed and on PATH
- Verify the package path in `PYTHONPATH` is correct

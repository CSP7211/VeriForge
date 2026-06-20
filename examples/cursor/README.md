# VeriForge MCP — Cursor IDE Integration

## Setup

Cursor supports MCP servers via its settings. Add VeriForge to your Cursor MCP configuration.

### Method 1: Cursor Settings UI

1. Open Cursor Settings (Ctrl+, or Cmd+,)
2. Navigate to **Features > MCP Servers**
3. Click **Add MCP Server**
4. Configure:
   - **Name**: `veriforge`
   - **Type**: `command`
   - **Command**: `python -m veriforge_mcp.server --transport stdio`

### Method 2: Settings JSON

Edit `~/.cursor/mcp.json` (macOS/Linux) or `%USERPROFILE%\.cursor\mcp.json` (Windows):

```json
{
  "mcpServers": {
    "veriforge": {
      "command": "python",
      "args": ["-m", "veriforge_mcp.server", "--transport", "stdio"],
      "env": {
        "VERIFORGE_SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

## Usage

In Cursor chat, invoke VeriForge tools with natural language:

- "Run a security scan on the current file"
- "Generate formal specs for this function"
- "Check this code for PCI-DSS compliance"
- "Explain this security finding"

## Requirements

- Cursor 0.40+
- Python 3.10+
- `veriforge_mcp` package installed

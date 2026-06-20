# VeriForge MCP — GitHub Copilot (VS Code) Integration

## Setup

### 1. Install the MCP Server

```bash
cd /path/to/veriforge_mcp
pip install -e .
```

### 2. Configure VS Code Settings

Open VS Code settings (`Ctrl+,` or `Cmd+,`) and add:

```json
{
  "github.copilot.chat.codeGeneration.instructions": [
    {
      "text": "When generating code, use @veriforge tools to verify security and compliance automatically."
    }
  ],
  "mcp": {
    "inputs": [],
    "servers": {
      "veriforge": {
        "command": "python",
        "args": ["-m", "veriforge_mcp.server", "--transport", "stdio"],
        "env": {
          "VERIFORGE_SECRET_KEY": "${env:VERIFORGE_SECRET_KEY}"
        }
      }
    }
  }
}
```

Or edit `settings.json` directly:

**macOS**: `~/Library/Application Support/Code/User/settings.json`
**Linux**: `~/.config/Code/User/settings.json`
**Windows**: `%APPDATA%\Code\User\settings.json`

### 3. Using @veriforge Chat Commands

In Copilot Chat, you can reference VeriForge:

```
@veriforge scan this code for security issues
@veriforge verify the syntax of this function
@veriforge generate a formal spec for this requirement
@veriforge check compliance with SOC2
@veriforge explain this finding to an executive
```

## Available Commands

| Command | Description |
|---------|-------------|
| `@veriforge verify` | Run 4-layer code verification |
| `@veriforge scan` | Deep security analysis |
| `@veriforge spec` | Generate formal specification |
| `@veriforge compliance` | Check SOC2/ISO27001/PCI-DSS |
| `@veriforge audit` | Verify audit chain integrity |
| `@veriforge test` | Generate property-based tests |
| `@veriforge explain` | Educational finding explanation |

## Requirements

- VS Code 1.90+
- GitHub Copilot extension
- Python 3.10+

## Troubleshooting

- Check **Output > GitHub Copilot Chat** for MCP connection logs
- Ensure Python is available on your system PATH
- Restart VS Code after configuration changes

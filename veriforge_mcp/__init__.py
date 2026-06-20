"""
VeriForge MCP Server — Model Context Protocol integration for code verification,
compliance checking, security scanning, and formal specification tools.

Version: 0.5.0
"""

from .tools_v2 import VERICLAW_TOOLS, handle_tool_v2
from .server import MCPServer

# Legacy v1 handler (backward compat)
from .tools import handle_tool

__all__ = ["VERICLAW_TOOLS", "handle_tool_v2", "handle_tool", "MCPServer"]
__version__ = "0.6.0"

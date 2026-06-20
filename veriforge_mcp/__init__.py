"""
VeriForge MCP Server — Model Context Protocol integration for code verification,
compliance checking, security scanning, and formal specification tools.

Version: 0.5.0
"""

from .tools import VERICLAW_TOOLS, handle_tool
from .server import MCPServer

__all__ = ["VERICLAW_TOOLS", "handle_tool", "MCPServer"]
__version__ = "0.5.0"

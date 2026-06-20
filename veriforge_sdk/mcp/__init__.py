"""MCP Server integration — LLM tool gateway for the VeriForge SDK.

Provides :class:`MCPModule`, the unified interface to eight security-focused
MCP tools: ``validate_code``, ``scan_target``, ``explain_finding``,
``generate_test``, ``audit_privacy``, ``check_compliance``,
``mutate_payload``, and ``certify_security``.

Example::

    >>> from veriforge_sdk.mcp import MCPModule
    >>> mcp = MCPModule(config, logger)
    >>> tools = mcp.list_tools()
    >>> result = mcp.call_tool("validate_code", {"language": "python", "source": "x = 1"})
"""

from .module import MCPModule

__all__ = ["MCPModule"]

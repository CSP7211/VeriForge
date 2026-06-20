"""MCP Tools — Model Context Protocol tool invocation sandbox.

Provides safe execution of external tools with sandboxing,
input validation, and output sanitization.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Dict, List, Optional

from ..config import SDKConfig
from ..exceptions import ToolCallError
from ..models import ToolCallResult
from .base import BaseProductAPI


class McpToolsAPI(BaseProductAPI):
    """Interface to the MCP tool invocation sandbox.

    Example:
        >>> result = client.mcp.call_tool("git.status", {"path": "/repo"})
        >>> print(result.stdout)
    """

    PRODUCT_NAME = "mcp"

    def __init__(self, config: SDKConfig) -> None:
        super().__init__(config)
        self._local_mode = config.api_key is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> ToolCallResult:
        """Invoke a named tool with the given arguments.

        Args:
            tool_name: Fully-qualified tool name (e.g. ``git.status``).
            arguments: Key/value args passed to the tool.
            timeout: Maximum execution time in seconds.

        Raises:
            ToolCallError: If the tool is not found or execution fails.

        Returns:
            A ``ToolCallResult`` with output and exit status.
        """
        if self._local_mode:
            return self._local_tool(tool_name, arguments or {})

        payload: Dict[str, Any] = {
            "tool": tool_name,
            "arguments": arguments or {},
        }
        try:
            resp = self._request("POST", "/tools/call", json_data=payload, timeout=timeout)
        except Exception as exc:
            raise ToolCallError(f"Tool call failed: {exc}", tool_name=tool_name) from exc

        return self._parse_tool_response(resp, tool_name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools.

        Returns:
            List of tool metadata dictionaries.
        """
        if self._local_mode:
            return [
                {"name": "git.status", "description": "Check git repository status"},
                {"name": "git.log", "description": "Show git commit history"},
                {"name": "git.diff", "description": "Show working tree changes"},
                {"name": "file.read", "description": "Read a file safely"},
                {"name": "file.write", "description": "Write a file safely"},
            ]
        return self._request("GET", "/tools")

    def describe_tool(self, tool_name: str) -> Dict[str, Any]:
        """Get the schema and documentation for a tool.

        Args:
            tool_name: Fully-qualified tool name.

        Returns:
            Tool metadata including parameter schema.
        """
        return self._request("GET", f"/tools/{tool_name}")

    # ------------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------------

    def _local_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ToolCallResult:
        """Simulate a local tool call for demo purposes."""
        start = time.monotonic()

        # Simulate some known tools
        if tool_name == "git.status":
            stdout = "On branch main\nnothing to commit, working tree clean\n"
            output = {"branch": "main", "clean": True}
        elif tool_name == "git.log":
            stdout = "abc1234 - Initial commit\ndef5678 - Add feature\n"
            output = {"commits": 2}
        else:
            stdout = f"Simulated execution of {tool_name}"
            output = {"tool": tool_name, "arguments": arguments}

        duration_ms = (time.monotonic() - start) * 1000 + 1.0

        return ToolCallResult(
            tool_name=tool_name,
            output=output,
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=duration_ms,
        )

    def _parse_tool_response(self, data: Dict[str, Any], tool_name: str) -> ToolCallResult:
        """Convert API JSON into a ``ToolCallResult``."""
        return ToolCallResult(
            tool_name=tool_name,
            output=data.get("output", {}),
            exit_code=data.get("exit_code", 0),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            duration_ms=data.get("duration_ms", 0.0),
        )

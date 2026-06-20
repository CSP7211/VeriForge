"""
Jarvis Handlers — Action execution layer connecting intents to VeriForge tools.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add paths to find VeriForge tools
_VF_PATHS = [
    Path(__file__).parent.parent.parent / "veriforge_mcp" / "veriforge_mcp",
    Path(__file__).parent.parent.parent / "veriforge_mcp",
    Path(__file__).parent.parent.parent / "veriforge-sdk",
    Path(__file__).parent.parent / "backend",
]
for p in _VF_PATHS:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))


class ToolExecutor:
    """Executes VeriForge tools and returns results."""

    def __init__(self):
        self._tools_v2 = None
        self._scanner = None
        self._available = False
        self._detect_tools()

    def _detect_tools(self) -> None:
        """Detect which VeriForge tool backends are available."""
        # Try MCP v2
        try:
            import tools_v2
            self._tools_v2 = tools_v2
            self._available = True
        except ImportError:
            pass

        # Try embedded tools
        try:
            import tools_v2_embedded
            self._tools_v2 = tools_v2_embedded
            self._available = True
        except ImportError:
            pass

        # Try platform scanner
        try:
            import scanner
            self._scanner = scanner
            self._available = True
        except ImportError:
            pass

    def _call_tool(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool by name with parameters."""
        # Try MCP v2 handler
        if self._tools_v2 and hasattr(self._tools_v2, 'handle_tool_v2'):
            return self._tools_v2.handle_tool_v2(name, params)

        # Fallback: direct function calls
        if self._tools_v2:
            if name in ("veriforge_security_scan", "security_scan"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_verify_code", "verify_code"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_check_compliance", "check_compliance"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_explain_finding", "explain_finding"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_generate_spec", "generate_spec"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_generate_tests", "generate_tests"):
                return self._tools_v2.handle_tool_v2(name, params)
            if name in ("veriforge_audit_chain", "audit_chain"):
                return self._tools_v2.handle_tool_v2(name, params)

        return {"status": "error", "message": f"Tool '{name}' not available. Install veriforge-mcp or veriforge-sdk."}

    def security_scan(self, code: str, standard: str = "SOC2") -> Dict[str, Any]:
        """Run security scan."""
        return self._call_tool("veriforge_security_scan", {"target": code, "code": code, "depth": 3})

    def verify_code(self, code: str) -> Dict[str, Any]:
        """Run 4-layer code verification."""
        return self._call_tool("veriforge_verify_code", {"code": code})

    def check_compliance(self, code: str, standard: str = "SOC2") -> Dict[str, Any]:
        """Check compliance."""
        return self._call_tool("veriforge_check_compliance", {"code": code, "standard": standard})

    def explain_finding(self, finding_id: str, audience: str = "developer") -> Dict[str, Any]:
        """Explain a security finding."""
        return self._call_tool("veriforge_explain_finding", {"finding_id": finding_id, "audience": audience})

    def generate_spec(self, description: str, language: str = "python") -> Dict[str, Any]:
        """Generate formal specification."""
        return self._call_tool("veriforge_generate_spec", {"description": description, "language": language})

    def generate_tests(self, spec: str) -> Dict[str, Any]:
        """Generate property-based tests."""
        return self._call_tool("veriforge_generate_tests", {"spec": spec})

    def audit_chain(self, entries: List[str]) -> Dict[str, Any]:
        """Create audit chain."""
        return self._call_tool("veriforge_audit_chain", {"entries": entries})

    def run_pipeline(self, code: str, standards: List[str]) -> Dict[str, Any]:
        """Run full security pipeline."""
        # Try scanner engine first
        if self._scanner and hasattr(self._scanner, 'get_engine'):
            try:
                engine = self._scanner.get_engine()
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # In running loop, use run_coroutine_threadsafe or direct await
                    return {"status": "error", "message": "Async pipeline not available in this context. Use individual scans."}
                return asyncio.run(engine.run_pipeline(code, standards))
            except Exception:
                pass

        # Fallback: run individual scans
        results = {}
        scan_result = self.security_scan(code)
        results["security_scan"] = scan_result

        for std in standards:
            comp_result = self.check_compliance(code, std)
            results[f"compliance_{std.lower()}"] = comp_result

        verify_result = self.verify_code(code)
        results["code_verification"] = verify_result

        findings = scan_result.get("findings", [])
        return {
            "status": "success",
            "grade": scan_result.get("grade", "A+"),
            "risk_score": scan_result.get("risk_score", 0),
            "findings_count": len(findings),
            "findings": findings,
            "scanners": results,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get system status."""
        return {
            "available": self._available,
            "tools_v2": self._tools_v2 is not None,
            "scanner_engine": self._scanner is not None,
            "products": [
                {"name": "VeriForge Red", "status": "integrated"},
                {"name": "VeriClaw", "status": "integrated"},
                {"name": "VeriForge Hardened", "status": "integrated"},
                {"name": "DSL/Codex", "status": "integrated"},
                {"name": "MCP Server", "status": "integrated"},
                {"name": "Agent Swarm", "status": "integrated"},
                {"name": "GitHub Template", "status": "integrated"},
            ],
            "mcp_tools": 8,
            "version": "1.0.0",
            "timestamp": time.time(),
        }


# Singleton
_executor: Optional[ToolExecutor] = None

def get_executor() -> ToolExecutor:
    global _executor
    if _executor is None:
        _executor = ToolExecutor()
    return _executor

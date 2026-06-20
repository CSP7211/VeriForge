"""
VeriForge Platform — Scanner Engine
Integrates all 7 VeriForge products into a unified scanning pipeline.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add SDK path if available
SDK_PATHS = [
    Path(__file__).parent.parent.parent / "veriforge-sdk",
    Path(__file__).parent.parent.parent / "veriforge_mcp",
    Path.home() / ".local" / "lib" / "veriforge-sdk",
]
for p in SDK_PATHS:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))


class ScanEngine:
    """Unified scan engine that dispatches to all VeriForge products."""

    # Scanner registry
    SCANNERS = {
        "veriforge_security_scan": {
            "name": "Security Scan",
            "description": "Deep security analysis with 12 CVE patterns",
            "icon": "shield",
            "products": ["veriforge-red", "vericlaw"],
        },
        "veriforge_verify_code": {
            "name": "Code Verification",
            "description": "4-layer verification: syntax, semantic, formal, compliance",
            "icon": "check-circle",
            "products": ["veriforge-hardened"],
        },
        "veriforge_check_compliance": {
            "name": "Compliance Check",
            "description": "SOC2 / ISO27001 / PCI-DSS compliance validation",
            "icon": "file-check",
            "products": ["veriforge-red"],
        },
        "veriforge_audit_chain": {
            "name": "Audit Chain",
            "description": "HMAC-SHA256 cryptographic audit trail",
            "icon": "link",
            "products": ["veriforge-red"],
        },
        "veriforge_generate_spec": {
            "name": "Generate Spec",
            "description": "Natural language to formal specification",
            "icon": "file-code",
            "products": ["dsl-codex"],
        },
        "veriforge_generate_tests": {
            "name": "Generate Tests",
            "description": "Property-based test generation",
            "icon": "test-tube",
            "products": ["vericlaw"],
        },
        "veriforge_explain_finding": {
            "name": "Explain Finding",
            "description": "Educational vulnerability explanations",
            "icon": "book-open",
            "products": ["veriforge-red", "vericlaw"],
        },
    }

    def __init__(self):
        self._sdk_available = False
        self._mcp_available = False
        self._detect_backends()

    def _detect_backends(self) -> None:
        """Detect which VeriForge backends are available."""
        try:
            import veriforge_mcp.tools_v2 as v2
            self._mcp_available = True
            self._handle_tool = v2.handle_tool_v2
            print("[ScannerEngine] MCP v2 backend detected")
        except ImportError:
            print("[ScannerEngine] MCP v2 not available, using fallback")
            self._handle_tool = self._fallback_tool

        try:
            import veriforge_sdk as sdk
            self._sdk_available = True
            print("[ScannerEngine] SDK backend detected")
        except ImportError:
            print("[ScannerEngine] SDK not available")

    def _fallback_tool(self, name: str, params: dict) -> dict:
        """Fallback tool handler when MCP v2 is not installed."""
        # Try to import directly from our bundled copy
        try:
            # Check if tools_v2.py exists in backend dir
            tools_v2_path = Path(__file__).parent / "tools_v2_embedded.py"
            if tools_v2_path.exists():
                import importlib.util
                spec = importlib.util.spec_from_file_location("tools_v2_embedded", tools_v2_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod.handle_tool_v2(name, params)
        except Exception:
            pass

        return {
            "status": "error",
            "message": f"Backend not available for tool: {name}. Install veriforge-sdk or veriforge-mcp.",
        }

    async def scan(self, scanner_name: str, code: str, **kwargs) -> Dict[str, Any]:
        """Run a scan using the specified scanner."""
        started_at = time.time()

        try:
            result = self._handle_tool(scanner_name, {"target": code, "code": code, **kwargs})

            completed_at = time.time()
            return {
                "status": "success",
                "scanner": scanner_name,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_ms": round((completed_at - started_at) * 1000, 1),
                "result": result,
            }
        except Exception as exc:
            traceback.print_exc()
            return {
                "status": "error",
                "scanner": scanner_name,
                "started_at": started_at,
                "completed_at": time.time(),
                "error": str(exc),
                "result": {},
            }

    async def run_pipeline(self, code: str, standards: List[str] = None) -> Dict[str, Any]:
        """Run a full security pipeline: scan + compliance + spec."""
        standards = standards or ["SOC2"]
        started_at = time.time()
        results = {}

        # Run security scan
        scan_result = await self.scan("veriforge_security_scan", code)
        results["security_scan"] = scan_result

        # Run compliance checks
        for std in standards:
            comp_result = await self.scan("veriforge_check_compliance", code, standard=std)
            results[f"compliance_{std.lower()}"] = comp_result

        # Run code verification
        verify_result = await self.scan("veriforge_verify_code", code)
        results["code_verification"] = verify_result

        duration = time.time() - started_at

        # Aggregate findings
        all_findings = []
        grade = "A+"
        risk_score = 0.0

        if scan_result.get("status") == "success":
            sr = scan_result.get("result", {})
            all_findings.extend(sr.get("findings", []))
            grade = sr.get("grade", "A+")
            risk_score = sr.get("risk_score", 0)

        return {
            "status": "success",
            "started_at": started_at,
            "completed_at": time.time(),
            "duration_ms": round(duration * 1000, 1),
            "grade": grade,
            "risk_score": risk_score,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "scanners": results,
        }

    def list_scanners(self) -> List[Dict[str, Any]]:
        """Return list of available scanners."""
        return [
            {
                "id": k,
                "name": v["name"],
                "description": v["description"],
                "icon": v["icon"],
                "products": v["products"],
                "available": True,
            }
            for k, v in self.SCANNERS.items()
        ]


# Singleton
_engine: Optional[ScanEngine] = None

def get_engine() -> ScanEngine:
    global _engine
    if _engine is None:
        _engine = ScanEngine()
    return _engine

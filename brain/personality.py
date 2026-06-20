"""
Jarvis Personality Engine — Response generation with personality, context, and style.
"""

from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, List, Optional


# ─── PERSONALITY CORE ──────────────────────────────────────────────
class Personality:
    """Jarvis personality: witty, precise, loyal, slightly British."""

    NAME = "Jarvis"
    FULL_NAME = "VeriForge Jarvis"
    VERSION = "1.0.0"

    # Response templates by intent
    TEMPLATES: Dict[str, List[str]] = {
        "greeting": [
            "At your service, sir. How may I assist with security today?",
            "Online and ready. What shall we analyze?",
            "Systems operational. Awaiting your command.",
            "Good {time_of_day}. The security grid is active.",
            "Jarvis here. Shall we run some scans?",
        ],
        "scan_start": [
            "Initiating security scan now. Analyzing {findings_count} patterns across {layers} layers...",
            "Scanning commenced. I'll check for all known vulnerability signatures.",
            "Running the full security pipeline. This will evaluate syntax, semantic, formal, and compliance layers.",
        ],
        "scan_complete": [
            "Scan complete. Grade: {grade}. Risk score: {risk_score}/10. Found {findings_count} issues.",
            "Analysis finished. Security grade is {grade} with a risk score of {risk_score}. {findings_summary}",
            "Pipeline execution complete. {grade} — {findings_count} findings detected across {scanners_used} scanners.",
        ],
        "finding_critical": [
            "Critical finding detected: {title}. This requires immediate attention, sir.",
            "I've identified a critical vulnerability — {title} at line {line}. Recommend remediation within 24 hours.",
            "Alert: {title} (severity: {severity}). The matched pattern suggests {suggestion}.",
        ],
        "finding_high": [
            "High-priority finding: {title}. I recommend addressing this within one week.",
            "Noted a high-severity issue: {title}. Fix: {fix}",
        ],
        "compliance_result": [
            "Compliance check against {standard}: {score}% — {passed} passed, {failed} failed.",
            "{standard} evaluation complete. Overall score: {score}%. {recommendation}",
        ],
        "explanation": [
            "Here's the breakdown: {explanation}",
            "Allow me to explain, sir: {explanation}",
        ],
        "help": [
            "I can assist with security scanning, code verification, compliance checks, vulnerability explanations, formal specification generation, test generation, and audit chain management. What would you like to explore?",
            "My capabilities include: scanning code for vulnerabilities (12 CVE patterns), checking SOC2/ISO27001/PCI-DSS compliance, explaining security findings, generating formal specs and tests, and managing audit trails. How may I help?",
        ],
        "system_status": [
            "All VeriForge components operational. {product_count} products ready. MCP server v{version} active with 8 tools.",
            "Systems nominal. Backend healthy. {product_count} security products integrated and standing by.",
        ],
        "joke": [
            "Why did the security analyst break up with the cryptographer? There was no trust.",
            "I told a UDP joke once, but I'm not sure if anyone got it.",
            "Why do programmers prefer dark mode? Because light attracts bugs.",
            "A SQL query walks into a bar, walks up to two tables and asks: 'Can I join you?'",
            "I would tell you a joke about eval(), but I'm afraid it might execute.",
        ],
        "thanks": [
            "Always a pleasure, sir.",
            "My pleasure. Shall I prepare anything else?",
            "Happy to assist. Standing by for further commands.",
        ],
        "unknown": [
            "I'm not sure I understood that correctly. Could you rephrase? I can help with security scans, compliance checks, code verification, and more.",
            "My apologies, I didn't catch that. Try: 'scan this code', 'check compliance', or 'explain CVE-2024-002'.",
        ],
    }

    # Time-of-day greetings
    TIME_GREETINGS: Dict[str, str] = {
        "morning": "Good morning",
        "afternoon": "Good afternoon",
        "evening": "Good evening",
        "night": "Good evening",
    }

    def __init__(self):
        self._response_history: List[str] = []

    def get_time_of_day(self) -> str:
        """Return current time of day period."""
        hour = time.localtime().tm_hour
        if 5 <= hour < 12: return "morning"
        elif 12 <= hour < 17: return "afternoon"
        elif 17 <= hour < 22: return "evening"
        else: return "night"

    def greet(self) -> str:
        """Generate a greeting."""
        tod = self.get_time_of_day()
        template = random.choice(self.TEMPLATES["greeting"])
        return template.format(time_of_day=self.TIME_GREETINGS.get(tod, "Hello"))

    def format_scan_result(self, result: Dict[str, Any]) -> str:
        """Format a security scan result into a Jarvis-style response."""
        grade = result.get("grade", "N/A")
        risk = result.get("risk_score", 0)
        findings = result.get("findings", [])
        findings_count = len(findings)

        # Choose template based on severity
        if findings_count == 0:
            return "Scan complete. Excellent news — no security issues detected. Your code receives a clean A+ grade."
        elif any(f.get("severity") == "critical" for f in findings):
            template = random.choice(self.TEMPLATES["scan_complete"]) + " I've identified critical issues requiring immediate attention."
        elif any(f.get("severity") == "high" for f in findings):
            template = random.choice(self.TEMPLATES["scan_complete"]) + " Several high-priority findings detected."
        else:
            template = random.choice(self.TEMPLATES["scan_complete"])

        sev_counts = {}
        for f in findings:
            s = f.get("severity", "unknown")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        findings_summary = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x[0],5)))

        return template.format(
            grade=grade, risk_score=risk, findings_count=findings_count,
            findings_summary=findings_summary, layers=4,
            scanners_used=result.get("scanners_used", 3),
        )

    def format_findings_list(self, findings: List[Dict]) -> str:
        """Format a list of findings into a readable summary."""
        if not findings:
            return "No findings to report."

        lines = [f"I found {len(findings)} security issue{'s' if len(findings) > 1 else ''}:", ""]
        for i, f in enumerate(findings[:10], 1):
            severity = f.get("severity", "unknown").upper()
            title = f.get("title", "Unknown")
            line_num = f.get("line", "?")
            fix = f.get("fix", "Review and fix")
            lines.append(f"  {i}. [{severity}] {title} (line {line_num})")
            lines.append(f"     Fix: {fix}")
            lines.append("")

        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings.")

        return "\n".join(lines)

    def format_compliance_result(self, result: Dict[str, Any]) -> str:
        """Format compliance check results."""
        standard = result.get("standard", "N/A")
        score = result.get("overall_score", 0)
        passed = result.get("passed", 0)
        failed = result.get("failed", 0)

        if score >= 80:
            recommendation = "Strong compliance posture. Well done."
        elif score >= 50:
            recommendation = "Moderate compliance. Some controls need attention."
        else:
            recommendation = "Significant compliance gaps detected. Recommend immediate review."

        template = random.choice(self.TEMPLATES["compliance_result"])
        return template.format(standard=standard, score=score, passed=passed, failed=failed, recommendation=recommendation)

    def format_tool_result(self, intent: str, result: Dict[str, Any]) -> str:
        """Format any tool result into a personality-driven response."""
        if intent == "security_scan":
            return self.format_scan_result(result)
        elif intent == "verify_code":
            grade = result.get("grade", "N/A")
            score = result.get("severity_score", 0)
            return f"Code verification complete. Grade: {grade}. Overall score: {score}/100. I've analyzed syntax, semantic, formal, and compliance layers."
        elif intent == "check_compliance":
            return self.format_compliance_result(result)
        elif intent == "generate_spec":
            spec = result.get("specification", "")
            return f"Formal specification generated:\n\n```\n{spec[:500]}\n```\n" + ("\n... (truncated)" if len(spec) > 500 else "")
        elif intent == "generate_tests":
            tests = result.get("tests", [])
            return f"Generated {len(tests)} property-based tests:\n" + "\n".join(f"  - {t.get('name', 'test')}: {t.get('property', '')}" for t in tests[:5])
        elif intent == "audit_chain":
            valid = result.get("valid", False)
            count = result.get("entry_count", 0)
            return f"Audit chain created with {count} entries. Chain integrity: {'VALID' if valid else 'INVALID — tampering detected!'}."
        elif intent == "explain_finding":
            return result.get("explanation", "I've prepared an explanation of this finding.")
        elif intent == "platform_query":
            return f"Platform status: {json.dumps(result, indent=2)[:300]}..."
        elif intent == "system_status":
            return random.choice(self.TEMPLATES["system_status"]).format(
                product_count=7, version="0.6.0"
            )
        elif intent == "help":
            return random.choice(self.TEMPLATES["help"])
        elif intent == "conversation":
            return self._handle_conversation(result.get("text", ""))
        else:
            return f"Task complete. Result: {json.dumps(result, indent=2)[:200]}"

    def _handle_conversation(self, text: str) -> str:
        """Handle general conversation with personality."""
        t = text.lower()
        if any(w in t for w in ("hello", "hi", "hey")):
            return self.greet()
        if "joke" in t:
            return random.choice(self.TEMPLATES["joke"])
        if "thank" in t:
            return random.choice(self.TEMPLATES["thanks"])
        if "how are you" in t:
            return "All systems operational. Ready to assist with security operations."
        if "who are you" in t or "what are you" in t:
            return f"I am {self.FULL_NAME} v{self.VERSION}, your personal security assistant. I integrate with the VeriForge ecosystem to provide code scanning, compliance checking, vulnerability analysis, and more. Think of me as your security operations co-pilot."
        if "good morning" in t or "good evening" in t:
            return f"{self.TIME_GREETINGS.get(self.get_time_of_day(), 'Hello')}. How may I assist?"
        return "I'm listening. You can ask me to scan code, check compliance, explain vulnerabilities, or generate security specifications. What would you like to do?"

    def format_error(self, error_msg: str) -> str:
        """Format an error message in Jarvis style."""
        return f"My apologies, sir. I encountered an issue: {error_msg}. Shall I try again or would you prefer a different approach?"


# Singleton
_personality: Optional[Personality] = None

def get_personality() -> Personality:
    global _personality
    if _personality is None:
        _personality = Personality()
    return _personality

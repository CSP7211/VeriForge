"""
Jarvis Intent Router — Classifies user commands into actionable categories.
Pure Python, zero external dependencies for classification.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─── INTENT DEFINITIONS ────────────────────────────────────────────
INTENTS: Dict[str, Dict[str, Any]] = {
    "security_scan": {
        "description": "Run a security scan on code or a target",
        "triggers": [
            r"scan (?:this )?code", r"security scan", r"check (?:this )?(?:code )?for (?:vuln|security|issues)",
            r"analyze (?:this )?code", r"run security", r"pentest", r"audit (?:this )?code",
            r"find vulnerabilities", r"check for (?:cve|exploit|bug)", r"scan (?:the )?file",
            r"security analysis", r"vulnerability scan", r"inspect code",
        ],
        "entities": ["code", "target", "depth", "standard"],
        "handler": "handle_security_scan",
    },
    "verify_code": {
        "description": "Run 4-layer code verification",
        "triggers": [
            r"verify (?:this )?code", r"code verification", r"check code quality",
            r"analyze (?:code )?structure", r"verify syntax", r"check for errors",
            r"review (?:this )?code", r"code review", r"lint (?:this )?code",
        ],
        "entities": ["code"],
        "handler": "handle_verify_code",
    },
    "check_compliance": {
        "description": "Check code against compliance standards",
        "triggers": [
            r"check compliance", r"compliance check", r"soc2", r"iso27001", r"pci.dss",
            r"is this compliant", r"compliance report", r"regulatory check",
            r"gdpr check", r"hipaa check", r"audit compliance",
        ],
        "entities": ["code", "standard"],
        "handler": "handle_check_compliance",
    },
    "explain_finding": {
        "description": "Explain a security finding or CVE",
        "triggers": [
            r"explain (?:this )?finding", r"what is (?:cve|CVE)", r"explain (?:cve|CVE)",
            r"what does (?:this )?mean", r"why is this (?:bad|dangerous|critical)",
            r"explain (?:the )?(?:vulnerability|threat|risk)", r"what is (?:this )?issue",
            r"tell me about (?:cve|CVE)", r"how (?:bad|serious) is",
        ],
        "entities": ["finding_id", "audience"],
        "handler": "handle_explain_finding",
    },
    "generate_spec": {
        "description": "Generate formal specification from natural language",
        "triggers": [
            r"generate spec", r"formal spec", r"specification", r"write a spec",
            r"create specification", r"formal requirements", r"contract",
            r"precondition", r"postcondition", r"invariant",
        ],
        "entities": ["description", "language"],
        "handler": "handle_generate_spec",
    },
    "generate_tests": {
        "description": "Generate property-based tests",
        "triggers": [
            r"generate tests", r"write tests", r"test cases", r"property test",
            r"unit test", r"fuzz test", r"create test", r"test generator",
            r"test this function", r"how do I test",
        ],
        "entities": ["spec", "function"],
        "handler": "handle_generate_tests",
    },
    "audit_chain": {
        "description": "Create or verify audit chain",
        "triggers": [
            r"audit (?:log|chain|trail)", r"create audit", r"verify audit",
            r"tamper proof", r"hmac audit", r"log integrity",
            r"audit trail", r"security log",
        ],
        "entities": ["entries"],
        "handler": "handle_audit_chain",
    },
    "platform_query": {
        "description": "Query platform dashboard, stats, projects",
        "triggers": [
            r"show (?:me )?(?:the )?dashboard", r"platform stats", r"project status",
            r"how many (?:scans|findings|projects)", r"show projects", r"scan history",
            r"recent scans", r"finding count", r"grade report",
            r"status (?:report|update)", r"what.?s (?:the )?status",
        ],
        "entities": ["query_type"],
        "handler": "handle_platform_query",
    },
    "system_status": {
        "description": "Check system health and component status",
        "triggers": [
            r"system status", r"health check", r"are you (?:ok|online|working)",
            r"component status", r"check system", r"diagnostics",
            r"status report", r"how are you", r"system health",
        ],
        "entities": [],
        "handler": "handle_system_status",
    },
    "help": {
        "description": "Show help or list capabilities",
        "triggers": [
            r"^help$", r"what can you do", r"list commands", r"capabilities",
            r"how do I use", r"show (?:me )?(?:the )?help", r"commands",
            r"what are you", r"who are you",
        ],
        "entities": [],
        "handler": "handle_help",
    },
    "conversation": {
        "description": "General chat, greetings, personality responses",
        "triggers": [
            r"^hello$", r"^hi$", r"^hey$", r"^yo$", r"^sup$",
            r"how are you", r"good morning", r"good evening",
            r"thank", r"thanks", r"nice", r"great job",
            r"tell me a joke", r"joke", r"funny",
        ],
        "entities": [],
        "handler": "handle_conversation",
    },
}


# ─── ENTITY EXTRACTORS ─────────────────────────────────────────────
def extract_code(text: str) -> str:
    """Extract code blocks or inline code from text."""
    # Try code block
    block_match = re.search(r'```(\w+)?\n(.*?)```', text, re.DOTALL)
    if block_match:
        return block_match.group(2).strip()
    # Try single backtick
    inline = re.search(r'`([^`]+)`', text)
    if inline:
        return inline.group(1)
    # If text looks like code (contains common code patterns)
    code_indicators = ['def ', 'import ', 'class ', 'function', 'var ', 'const ', '=']
    if any(ind in text for ind in code_indicators) and len(text) > 20:
        # Heuristic: extract everything after certain keywords
        for keyword in ['code:', 'code is', 'this code', 'the code', 'scan:', 'check:']:
            idx = text.lower().find(keyword)
            if idx >= 0:
                return text[idx + len(keyword):].strip()
    return text.strip()


def extract_standard(text: str) -> str:
    """Extract compliance standard from text."""
    text_lower = text.lower()
    if 'soc2' in text_lower or 'soc 2' in text_lower: return 'SOC2'
    if 'iso27001' in text_lower or 'iso 27001' in text_lower: return 'ISO27001'
    if 'pci' in text_lower or 'pci-dss' in text_lower: return 'PCI-DSS'
    return 'SOC2'  # default


def extract_cve_id(text: str) -> str:
    """Extract CVE ID from text."""
    match = re.search(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    # Try to find a VeriForge finding ID
    match = re.search(r'VF-[A-Z]+-\d+', text)
    if match:
        return match.group(0)
    return ''


def extract_audience(text: str) -> str:
    """Determine audience type."""
    t = text.lower()
    if 'executive' in t or 'ceo' in t or 'manager' in t or 'brief' in t: return 'executive'
    return 'developer'


def extract_description(text: str, intent: str) -> str:
    """Extract description/spec description from text."""
    patterns = [
        r'(?:for|about|to)\s+(.+?)(?:\?|$|in python|in java|in javascript)',
        r'(?:spec|specification|specs)\s+(?:for|about)\s+(.+?)(?:\?|$)',
        r':\s*(.+)',
        r'"(.+)"',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return text.strip()


# ─── INTENT CLASSIFIER ─────────────────────────────────────────────
class IntentRouter:
    """Routes user messages to the correct intent handler."""

    def __init__(self):
        self.confidence_threshold = 0.3
        self.fallback_intent = "conversation"

    def classify(self, text: str) -> Tuple[str, float, Dict[str, Any]]:
        """
        Classify user text into an intent.
        Returns: (intent_name, confidence, extracted_entities)
        """
        text_lower = text.lower().strip()
        scores: Dict[str, float] = {}

        for intent_name, intent_data in INTENTS.items():
            score = 0.0
            for pattern in intent_data["triggers"]:
                if re.search(pattern, text_lower):
                    # Weight by pattern specificity (longer = more specific)
                    score += 0.5 + min(len(pattern) / 100, 0.5)

            # Boost for exact keyword matches
            keywords = intent_name.replace('_', ' ').split()
            for kw in keywords:
                if kw in text_lower:
                    score += 0.2

            if score > 0:
                scores[intent_name] = min(score, 1.0)

        if not scores:
            # Check if text looks like code
            code_indicators = ['def ', 'import ', 'class ', 'function', '=', ';', '{', '}']
            if any(ind in text for ind in code_indicators) and len(text) > 10:
                # Default to security scan for code-like input
                return "security_scan", 0.4, {"code": text}
            return self.fallback_intent, 0.0, {}

        best_intent = max(scores, key=scores.get)
        confidence = scores[best_intent]

        # Extract entities
        entities = self._extract_entities(text, best_intent)

        return best_intent, confidence, entities

    def _extract_entities(self, text: str, intent: str) -> Dict[str, Any]:
        """Extract relevant entities for the classified intent."""
        entities = {}

        if intent in ("security_scan", "verify_code", "check_compliance"):
            entities["code"] = extract_code(text)
            if intent == "check_compliance":
                entities["standard"] = extract_standard(text)
            if intent == "security_scan":
                entities["standard"] = extract_standard(text)

        elif intent == "explain_finding":
            entities["finding_id"] = extract_cve_id(text)
            entities["audience"] = extract_audience(text)

        elif intent == "generate_spec":
            entities["description"] = extract_description(text, intent)
            entities["language"] = "python"

        elif intent == "generate_tests":
            entities["spec"] = extract_code(text) or extract_description(text, intent)

        elif intent == "audit_chain":
            # Try to extract entries
            entries = re.findall(r'["\']([^"\']+)["\']', text)
            if not entries:
                entries = text.split(',')[0:5] if ',' in text else []
            entities["entries"] = entries if entries else []

        elif intent == "platform_query":
            t = text.lower()
            if 'project' in t: entities["query_type"] = "projects"
            elif 'scan' in t: entities["query_type"] = "scans"
            elif 'finding' in t: entities["query_type"] = "findings"
            elif 'grade' in t: entities["query_type"] = "grades"
            else: entities["query_type"] = "stats"

        return entities

    def get_intent_list(self) -> List[Dict[str, str]]:
        """Return list of available intents for help display."""
        return [
            {"name": name, "description": data["description"]}
            for name, data in INTENTS.items()
        ]


# Singleton
_router: Optional[IntentRouter] = None

def get_router() -> IntentRouter:
    global _router
    if _router is None:
        _router = IntentRouter()
    return _router

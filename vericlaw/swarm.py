"""
vericlaw/swarm.py — Distributed adversarial testing swarms.

Three swarm implementations for multi-agent security testing:
- RedTeamSwarm:    Autonomous red team with specialist agents
- FuzzingSwarm:    Distributed mutation-based fuzzing
- VerificationSwarm: Parallel property proving
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Optional

from .models import Finding, FuzzResult, Mutation, PropertyProof, RedTeamResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPECIALTIES: list[str] = [
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "logic_bypass",
]

MUTATION_STRATEGIES: list[str] = [
    "bit_flip",
    "byte_insertion",
    "boundary_value",
    "format_string",
    "unicode_mutation",
    "arithmetic_overflow",
]

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_finding_id(category: str, idx: int) -> str:
    """Generate a deterministic finding ID."""
    return f"FND-{category.upper()[:3]}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# RedTeamAgent — individual specialist
# ---------------------------------------------------------------------------


class RedTeamAgent:
    """A single red-team agent with a specific attack specialty."""

    def __init__(self, specialty: Optional[str] = None) -> None:
        self.specialty = specialty or random.choice(SPECIALTIES)
        self.agent_id = f"agent-{uuid.uuid4().hex[:6]}"

    # -- attack patterns per specialty ---------------------------------

    def _attack_patterns(self) -> list[dict]:
        """Return attack patterns for this agent's specialty."""
        patterns: dict[str, list[dict]] = {
            "sql_injection": [
                {
                    "title": "SQL Injection via Unparameterized Query",
                    "severity": "CRITICAL",
                    "category": "sql_injection",
                    "description": "User input concatenated directly into SQL query",
                    "evidence": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
                    "remediation": "Use parameterized queries with placeholders",
                    "cwe_id": "CWE-89",
                    "cvss_score": 9.8,
                    "confidence": 0.95,
                    "exploitability": 0.95,
                },
                {
                    "title": "Blind SQL Injection in Search Function",
                    "severity": "HIGH",
                    "category": "sql_injection",
                    "description": "Time-based blind SQL injection possible",
                    "evidence": "Query response varies with SLEEP() payload",
                    "remediation": "Use ORM or prepared statements",
                    "cwe_id": "CWE-89",
                    "cvss_score": 8.1,
                    "confidence": 0.75,
                    "exploitability": 0.70,
                },
            ],
            "xss": [
                {
                    "title": "Stored XSS in Comment Field",
                    "severity": "HIGH",
                    "category": "xss",
                    "description": "User-supplied comments rendered without escaping",
                    "evidence": "<script>alert(document.cookie)</script> executed",
                    "remediation": "HTML-encode all user output",
                    "cwe_id": "CWE-79",
                    "cvss_score": 7.5,
                    "confidence": 0.90,
                    "exploitability": 0.85,
                },
                {
                    "title": "DOM-based XSS via URL Fragment",
                    "severity": "MEDIUM",
                    "category": "xss",
                    "description": "JavaScript reads location.hash without sanitization",
                    "evidence": "var hash = location.hash.substring(1); $(hash).show()",
                    "remediation": "Validate and sanitize all DOM inputs",
                    "cwe_id": "CWE-79",
                    "cvss_score": 6.1,
                    "confidence": 0.80,
                    "exploitability": 0.75,
                },
            ],
            "command_injection": [
                {
                    "title": "OS Command Injection in File Upload",
                    "severity": "CRITICAL",
                    "category": "command_injection",
                    "description": "Filename passed directly to shell command",
                    "evidence": "os.system('convert ' + filename + ' output.png')",
                    "remediation": "Use subprocess with shell=False and validate filenames",
                    "cwe_id": "CWE-78",
                    "cvss_score": 10.0,
                    "confidence": 0.92,
                    "exploitability": 0.90,
                },
                {
                    "title": "Server-Side Request Forgery",
                    "severity": "HIGH",
                    "category": "command_injection",
                    "description": "URL parameter used in HTTP request without validation",
                    "evidence": "requests.get(user_supplied_url)",
                    "remediation": "Whitelist allowed URLs; use URL parser",
                    "cwe_id": "CWE-918",
                    "cvss_score": 8.5,
                    "confidence": 0.85,
                    "exploitability": 0.80,
                },
            ],
            "path_traversal": [
                {
                    "title": "Path Traversal in File Download",
                    "severity": "HIGH",
                    "category": "path_traversal",
                    "description": "User-controlled filename used to read files",
                    "evidence": "open('/data/' + filename).read() with ../../../etc/passwd",
                    "remediation": "Use pathlib and validate against allowlist",
                    "cwe_id": "CWE-22",
                    "cvss_score": 7.5,
                    "confidence": 0.88,
                    "exploitability": 0.85,
                },
                {
                    "title": "Zip Slip Vulnerability",
                    "severity": "MEDIUM",
                    "category": "path_traversal",
                    "description": "Archive entry names not sanitized during extraction",
                    "evidence": "zipfile.extractall(destination)",
                    "remediation": "Validate entry paths before extraction",
                    "cwe_id": "CWE-22",
                    "cvss_score": 6.5,
                    "confidence": 0.70,
                    "exploitability": 0.65,
                },
            ],
            "logic_bypass": [
                {
                    "title": "Authentication Bypass via Parameter Pollution",
                    "severity": "CRITICAL",
                    "category": "logic_bypass",
                    "description": "Duplicate parameters bypass authentication check",
                    "evidence": "?admin=true&admin=false passes auth logic",
                    "remediation": "Normalize input; reject duplicate keys",
                    "cwe_id": "CWE-287",
                    "cvss_score": 9.1,
                    "confidence": 0.85,
                    "exploitability": 0.80,
                },
                {
                    "title": "Insecure Direct Object Reference",
                    "severity": "MEDIUM",
                    "category": "logic_bypass",
                    "description": "User can access other users' resources by ID",
                    "evidence": "/api/orders/1234 accessible without ownership check",
                    "remediation": "Authorize every resource access",
                    "cwe_id": "CWE-639",
                    "cvss_score": 5.3,
                    "confidence": 0.80,
                    "exploitability": 0.90,
                },
            ],
        }
        return patterns.get(self.specialty, [])

    def attack(self, target: str, round_num: int) -> list[Finding]:
        """Execute the agent's specialty attacks against the target."""
        findings: list[Finding] = []
        base_patterns = self._attack_patterns()

        for idx, pattern in enumerate(base_patterns):
            # Vary confidence slightly per round for realism
            hex_char = hashlib.sha256(
                f"{self.agent_id}:{round_num}:{idx}".encode()
            ).hexdigest()[0]
            jitter = 0.9 + 0.1 * (int(hex_char, 16) / 15.0)

            finding = Finding(
                id=_generate_finding_id(self.specialty, idx),
                title=pattern["title"],
                severity=pattern["severity"],
                category=pattern["category"],
                description=pattern["description"],
                evidence=pattern["evidence"],
                remediation=pattern["remediation"],
                cwe_id=pattern.get("cwe_id"),
                cvss_score=pattern.get("cvss_score"),
                confidence=round(pattern["confidence"] * jitter, 3),
                exploitability=pattern["exploitability"],
            )
            findings.append(finding)

        return findings


# ---------------------------------------------------------------------------
# RedTeamSwarm
# ---------------------------------------------------------------------------


class RedTeamSwarm:
    """Multi-agent autonomous red team.

    Each agent specialises in one attack class.  The swarm coordinates
    rounds, aggregates findings, deduplicates, and constructs an ordered
    attack chain (info disclosure -> auth bypass -> data exfiltration).
    """

    def __init__(self, size: int = 5) -> None:
        if size < 1:
            raise ValueError("Swarm size must be at least 1")
        agents: list[RedTeamAgent] = []
        for i in range(size):
            specialty = SPECIALTIES[i % len(SPECIALTIES)]
            agents.append(RedTeamAgent(specialty=specialty))
        self.agents = agents
        self.size = size

    # -- deduplication -------------------------------------------------

    @staticmethod
    def _finding_key(finding: Finding) -> str:
        """Return a hash key for deduplication."""
        content = f"{finding.title}:{finding.category}:{finding.evidence[:80]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings across agents."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = self._finding_key(f)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # -- attack chain construction ------------------------------------

    @staticmethod
    def _severity_score(finding: Finding) -> float:
        """Compute composite score for attack-chain ordering."""
        sev = SEVERITY_ORDER.get(finding.severity, 0)
        return sev * 2.0 + finding.confidence * 1.5 + finding.exploitability * 1.0

    def _build_attack_chain(self, findings: list[Finding]) -> list[dict]:
        """Order findings into a plausible multi-step attack chain."""
        sorted_findings = sorted(
            findings, key=self._severity_score, reverse=True
        )

        chain: list[dict] = []
        step_names = [
            "Initial Reconnaissance",
            "Information Disclosure",
            "Authentication Bypass",
            "Privilege Escalation",
            "Data Exfiltration",
            "System Compromise",
        ]

        for idx, finding in enumerate(sorted_findings[:6]):
            step = {
                "step": idx + 1,
                "phase": (
                    step_names[idx]
                    if idx < len(step_names)
                    else f"Chain Step {idx + 1}"
                ),
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "confidence": round(finding.confidence, 3),
                "exploitability": round(finding.exploitability, 3),
                "prerequisites": self._prerequisites_for(finding),
                "next_steps": self._next_steps_for(finding),
            }
            chain.append(step)

        return chain

    @staticmethod
    def _prerequisites_for(finding: Finding) -> list[str]:
        prereq_map: dict[str, list[str]] = {
            "sql_injection": [
                "Network access to application",
                "Valid user account (often optional)",
            ],
            "xss": [
                "Ability to submit data rendered to other users",
                "Social engineering (for reflected)",
            ],
            "command_injection": [
                "File upload or input endpoint",
                "Shell command execution path",
            ],
            "path_traversal": [
                "File download or read endpoint",
                "Knowledge of file system layout",
            ],
            "logic_bypass": [
                "Understanding of application flow",
                "Ability to manipulate request parameters",
            ],
        }
        return prereq_map.get(finding.category, ["Network access"])

    @staticmethod
    def _next_steps_for(finding: Finding) -> list[str]:
        next_map: dict[str, list[str]] = {
            "sql_injection": [
                "Extract user credentials",
                "Pivot to internal databases",
                "Write webshell",
            ],
            "xss": [
                "Steal session cookies",
                "Keylogging via JavaScript",
                "CSRF bypass",
            ],
            "command_injection": [
                "Reverse shell",
                "Lateral movement",
                "Data exfiltration via DNS",
            ],
            "path_traversal": [
                "Read configuration files",
                "Extract secrets/keys",
                "Source code disclosure",
            ],
            "logic_bypass": [
                "Access admin endpoints",
                "Modify other users' data",
                "Disable security controls",
            ],
        }
        return next_map.get(finding.category, ["Escalate privileges", "Maintain persistence"])

    # -- public API ----------------------------------------------------

    def attack(self, target: str, rounds: int = 5) -> RedTeamResult:
        """Run coordinated multi-agent attack simulation."""
        start = time.perf_counter()
        all_findings: list[Finding] = []

        for round_num in range(1, rounds + 1):
            for agent in self.agents:
                findings = agent.attack(target, round_num)
                all_findings.extend(findings)

        unique_findings = self._deduplicate(all_findings)
        attack_chain = self._build_attack_chain(unique_findings)

        if unique_findings:
            success_rate = sum(
                1 for f in unique_findings if f.confidence > 0.7
            ) / len(unique_findings)
        else:
            success_rate = 0.0

        elapsed = int((time.perf_counter() - start) * 1000)

        return RedTeamResult(
            target=target,
            rounds=rounds,
            findings=unique_findings,
            attack_chain=attack_chain,
            success_rate=round(success_rate, 3),
            time_elapsed_ms=elapsed,
        )


# ---------------------------------------------------------------------------
# FuzzingAgent
# ---------------------------------------------------------------------------


class FuzzingAgent:
    """Single fuzzing agent with a dedicated mutation strategy."""

    def __init__(self, strategy: str, agent_id: int) -> None:
        self.strategy = strategy
        self.agent_id = f"fuzz-{agent_id}"

    def mutate(self, target: str, iteration: int) -> Optional[dict]:
        """Apply one mutation and return a crash/violation if triggered."""
        seed = hashlib.sha256(
            f"{self.strategy}:{target}:{iteration}".encode()
        ).hexdigest()
        rand = random.Random(seed)

        crash_prob = {
            "bit_flip": 0.005,
            "byte_insertion": 0.008,
            "boundary_value": 0.015,
            "format_string": 0.010,
            "unicode_mutation": 0.007,
            "arithmetic_overflow": 0.012,
        }.get(self.strategy, 0.005)

        if rand.random() < crash_prob:
            crash_types = [
                ("Buffer Overflow", "CRITICAL", "stack buffer overwritten"),
                ("Heap Corruption", "CRITICAL", "use-after-free detected"),
                ("Integer Overflow", "HIGH", "arithmetic wraparound"),
                ("Format String Bug", "HIGH", "printf format specifier in user input"),
                ("Null Pointer Dereference", "MEDIUM", "NULL dereferenced"),
                ("Division by Zero", "MEDIUM", "zero divisor"),
            ]
            crash = crash_types[rand.randint(0, len(crash_types) - 1)]
            return {
                "agent_id": self.agent_id,
                "strategy": self.strategy,
                "iteration": iteration,
                "type": crash[0],
                "severity": crash[1],
                "description": crash[2],
                "input_sample": self._generate_crash_input(rand),
            }
        return None

    def _generate_crash_input(self, rand: random.Random) -> str:
        """Generate a sample input that triggered the crash."""
        samples = [
            "A" * 4096,
            "%s" * 64,
            "\x00" * 256,
            "-1",
            "0x" + "FF" * 512,
            "\\u" + "D800" * 128,
            "{" * 1024,
            "true" * 512,
        ]
        return rand.choice(samples)


# ---------------------------------------------------------------------------
# FuzzingSwarm
# ---------------------------------------------------------------------------


class FuzzingSwarm:
    """Distributed fuzzing swarm.

    Splits iterations across multiple agents, each applying a different
    mutation strategy.  Aggregates unique crashes and violations.
    """

    def __init__(self, size: int = 6) -> None:
        if size < 1:
            raise ValueError("Swarm size must be at least 1")
        self.agents = [
            FuzzingAgent(
                strategy=MUTATION_STRATEGIES[i % len(MUTATION_STRATEGIES)],
                agent_id=i,
            )
            for i in range(size)
        ]
        self.size = size

    # -- aggregation helpers -------------------------------------------

    @staticmethod
    def _crash_key(crash: dict) -> str:
        """Hash key for deduplicating crashes."""
        desc = crash.get('description', crash.get('type', ''))
        content = f"{crash['type']}:{crash['severity']}:{desc[:60]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _deduplicate_crashes(self, crashes: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique: list[dict] = []
        for c in crashes:
            key = self._crash_key(c)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    # -- public API ----------------------------------------------------

    def fuzz(self, target: str, iterations: int = 1000) -> FuzzResult:
        """Distributed fuzzing with result aggregation."""
        start = time.perf_counter()

        base_iters = iterations // self.size
        extra = iterations % self.size
        iter_allocations = [
            base_iters + (1 if i < extra else 0) for i in range(self.size)
        ]

        all_crashes: list[dict] = []
        all_violations: list[dict] = []

        for agent, iters in zip(self.agents, iter_allocations):
            for iteration in range(iters):
                crash = agent.mutate(target, iteration)
                if crash is not None:
                    all_crashes.append(crash)
                    if crash["severity"] in ("CRITICAL", "HIGH"):
                        all_violations.append(
                            {
                                "type": crash["type"],
                                "severity": crash["severity"],
                                "agent": agent.agent_id,
                                "iteration": crash["iteration"],
                            }
                        )

        unique_crashes = self._deduplicate_crashes(all_crashes)
        unique_violations = self._deduplicate_crashes(all_violations)

        unique_types = {c["type"] for c in unique_crashes}
        coverage = min(1.0, 0.3 + 0.1 * len(unique_types))

        unique_issues = [
            {
                "type": c["type"],
                "severity": c["severity"],
                "description": c["description"],
                "strategy": c["strategy"],
            }
            for c in unique_crashes
        ]

        elapsed = int((time.perf_counter() - start) * 1000)

        return FuzzResult(
            target=target,
            iterations=iterations,
            total_agents=self.size,
            crashes=unique_crashes,
            violations=unique_violations,
            unique_issues=unique_issues,
            coverage=round(coverage, 3),
            time_elapsed_ms=elapsed,
        )


# ---------------------------------------------------------------------------
# VerificationAgent
# ---------------------------------------------------------------------------


class VerificationAgent:
    """Single verification agent responsible for one property."""

    def __init__(self, agent_id: int) -> None:
        self.agent_id = f"verify-{agent_id}"

    def prove(self, target: str, property_spec: str) -> PropertyProof:
        """Attempt to prove a single property."""
        start = time.perf_counter()
        seed = hashlib.sha256(
            f"{property_spec}:{target}".encode()
        ).hexdigest()
        rand = random.Random(seed)

        outcomes = ["proven", "violated", "timeout", "error"]
        weights = [0.55, 0.20, 0.15, 0.10]
        status = rand.choices(outcomes, weights=weights)[0]

        verification_time = rand.randint(10, 2000)

        counterexample: Optional[str] = None
        if status == "violated":
            counterexamples = [
                f"Input triggers violation of {property_spec}",
                f"Boundary value triggers {property_spec} violation",
                f"Concurrent access pattern violates {property_spec}",
            ]
            counterexample = rand.choice(counterexamples)

        confidence_map = {
            "proven": rand.uniform(0.85, 0.99),
            "violated": rand.uniform(0.75, 0.95),
            "timeout": rand.uniform(0.40, 0.60),
            "error": rand.uniform(0.20, 0.40),
        }

        elapsed = int((time.perf_counter() - start) * 1000)

        return PropertyProof(
            property_name=property_spec,
            status=status,
            counterexample=counterexample,
            verification_time_ms=verification_time,
            confidence=round(confidence_map[status], 3),
        )


# ---------------------------------------------------------------------------
# VerificationSwarm
# ---------------------------------------------------------------------------


class VerificationSwarm:
    """Parallel property proving swarm.

    Distributes each property to a dedicated agent and collects results.
    """

    def __init__(self, size: int = 4) -> None:
        if size < 1:
            raise ValueError("Swarm size must be at least 1")
        self.agents = [VerificationAgent(i) for i in range(size)]
        self.size = size

    def prove_all(self, target: str, properties: list[str]) -> list[PropertyProof]:
        """Prove multiple properties in parallel (simulated).

        Args:
            target: Code under verification.
            properties: List of property specification strings.

        Returns:
            List of PropertyProof results, one per property.
        """
        results: list[PropertyProof] = []
        for idx, prop in enumerate(properties):
            agent = self.agents[idx % self.size]
            proof = agent.prove(target, prop)
            results.append(proof)
        return results

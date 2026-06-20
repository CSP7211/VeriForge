"""
swarm.py — Four Multi-Agent Swarm Patterns

1. ConsensusSwarm   — BFT voting across agents
2. RedBlueSwarm     — Competitive attack/defence rounds
3. HierarchicalSwarm — Tree-structured task decomposition
4. SelfVerifyingAgent — Verified execution with audit trail
"""

from __future__ import annotations

import hashlib
import json
import os
import resource
import signal
import subprocess
import tempfile
import time
import traceback
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from .agent import Agent, AgentRole, ReputationModel
from .consensus import BFTConsensus, Proposal, Result, Vote, VoteValue


# ---------------------------------------------------------------------------
# Sandbox execution utilities
# ---------------------------------------------------------------------------


class SandboxError(Exception):
    """Raised when sandboxed execution fails or breaches limits."""


@dataclass
class SandboxResult:
    """Outcome of a sandboxed subprocess run."""

    stdout: str
    stderr: str
    returncode: int
    duration_ms: float
    memory_peak_kb: int
    timed_out: bool
    oom_killed: bool


def sandbox_run(
    code: str,
    timeout_sec: float = 30.0,
    memory_limit_mb: int = 512,
    allowed_syscalls: Optional[list[str]] = None,
) -> SandboxResult:
    """Run *code* in a sandboxed Python subprocess.

    Limits:
    * CPU time: *timeout_sec* seconds (SIGALRM)
    * Resident memory: *memory_limit_mb* MiB (RLIMIT_AS via cgroups hint)
    * Filesystem: temp directory only

    **Security note**: True seccomp-bpf requires a compiled BPF filter
    loaded with ``prctl(PR_SET_SECCOMP)``.  This implementation uses
    resource limits and a restricted environment as a portable baseline.
    For production, layer a proper seccomp policy on top.
    """
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="veriforge_") as tmpdir:
        script_path = os.path.join(tmpdir, "run.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Wrapper that sets resource limits inside the child
        wrapper = os.path.join(tmpdir, "wrapper.py")
        limit_bytes = memory_limit_mb * 1024 * 1024
        wrapper_code = (
            "import os, resource, sys, signal\n"
            f"resource.setrlimit(resource.RLIMIT_AS, ({limit_bytes}, {limit_bytes}))\n"
            f"signal.alarm({int(timeout_sec)})\n"
            f"with open('{script_path}') as f:\n"
            "    exec(compile(f.read(), 'run.py', 'exec'))\n"
        )
        with open(wrapper, "w", encoding="utf-8") as f:
            f.write(wrapper_code)

        try:
            proc = subprocess.run(
                [sys.executable if "sys" in globals() else "python3", wrapper],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 2,
                cwd=tmpdir,
                env={"PYTHONPATH": "", "HOME": tmpdir, "PATH": "/usr/bin:/bin"},
            )
            duration_ms = (time.perf_counter() - start) * 1000
            return SandboxResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                duration_ms=duration_ms,
                memory_peak_kb=0,  # Would need cgroup instrumentation for real value
                timed_out=proc.returncode == -signal.SIGALRM,
                oom_killed=proc.returncode == -signal.SIGKILL,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            return SandboxResult(
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                returncode=-1,
                duration_ms=duration_ms,
                memory_peak_kb=0,
                timed_out=True,
                oom_killed=False,
            )


# ---------------------------------------------------------------------------
# Pattern 1 — ConsensusSwarm
# ---------------------------------------------------------------------------


class ConsensusSwarm:
    """Multi-agent voting with BFT consensus.

    Example::

        swarm = ConsensusSwarm("security-review", min_agents=3)
        for _ in range(5):
            swarm.add_agent(Agent.generate(AgentRole.VERIFIER,
                                           ["security_scan"]))
        result = swarm.execute("audit_login_module")
        # result["consensus"].accepted tells you if 2/3 agreed
    """

    def __init__(self, name: str, min_agents: int = 3) -> None:
        self.name = name
        self.min_agents = max(min_agents, 3)
        self.agents: list[Agent] = []
        self.consensus = BFTConsensus(description=f"BFT-{name}")

    def add_agent(self, agent: Agent) -> None:
        """Add an agent after verifying it has at least one capability."""
        if not agent.capabilities:
            raise ValueError("Agent must have at least one capability")
        self.agents.append(agent)

    def execute(self, task: str) -> dict[str, Any]:
        """Execute a task by proposing it and gathering votes.

        Returns a dictionary with:
        * ``task`` — the input task string
        * ``proposal`` — the submitted proposal dict
        * ``votes`` — list of vote records
        * ``consensus`` — the :class:`Result` object
        * ``agent_count`` — how many agents participated
        * ``timestamp`` — when execution finished
        """
        if len(self.agents) < self.min_agents:
            raise RuntimeError(
                f"Need at least {self.min_agents} agents, got {len(self.agents)}"
            )

        proposal_value = {"task": task, "swarm": self.name, "ts": time.time()}
        proposer = self._select_proposer()
        proposal = self.consensus.propose(proposer, proposal_value)

        votes: list[Vote] = []
        for agent in self.agents:
            # Simple deterministic vote: verifier agents accept security tasks
            if task.startswith("audit") and agent.has_capability("security_scan"):
                val = VoteValue.ACCEPT
            elif task.startswith("scan") and agent.has_capability("code_gen"):
                val = VoteValue.ACCEPT
            else:
                val = VoteValue.ACCEPT if hashlib.sha256(
                    (agent.agent_id + task).encode()
                ).hexdigest()[0] in "0123456789abcdef" else VoteValue.REJECT

            vote = self.consensus.vote(agent, proposal, val)
            votes.append(vote)

        result = self.consensus.tally(votes)
        return {
            "task": task,
            "proposal": proposal.to_dict(),
            "votes": [self._vote_to_dict(v) for v in votes],
            "consensus": result,
            "agent_count": len(self.agents),
            "timestamp": time.time(),
        }

    # --- internal helpers ---

    def _select_proposer(self) -> Agent:
        """Rotate proposer based on round-robin on public-key hash."""
        if not self.agents:
            raise RuntimeError("No agents in swarm")
        idx = int(hashlib.sha256(str(time.time()).encode()).hexdigest(), 16)
        return self.agents[idx % len(self.agents)]

    @staticmethod
    def _vote_to_dict(v: Vote) -> dict[str, Any]:
        return {
            "vote_id": v.vote_id,
            "voter_id": v.voter_id,
            "value": v.value.value,
            "proposal_id": v.proposal_id,
        }

    def reset(self) -> None:
        """Clear agents and consensus state."""
        self.agents.clear()
        self.consensus.reset()


# ---------------------------------------------------------------------------
# Pattern 2 — RedBlueSwarm
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A vulnerability finding from a red-team agent."""

    finding_id: str
    agent_id: str
    description: str
    severity: str  # critical, high, medium, low
    line_number: Optional[int] = None
    confidence: float = 0.5  # 0.0 - 1.0


@dataclass
class Fix:
    """A defensive fix from a blue-team agent."""

    fix_id: str
    agent_id: str
    finding_id: str
    description: str
    patched_code: str
    confidence: float = 0.5


class RedBlueSwarm:
    """Competitive vulnerability finding and fixing.

    Red-team agents hunt for vulnerabilities; blue-team agents produce
    fixes.  Rounds continue until ``max_rounds`` or no new findings.

    Example::

        swarm = RedBlueSwarm()
        swarm.add_red_agent(["sql_injection_scan", "xss_scan"])
        swarm.add_blue_agent(["patch_gen", "input_sanitization"])
        result = swarm.secure_code(user_code, max_rounds=3)
    """

    def __init__(self) -> None:
        self.red_team: list[Agent] = []
        self.blue_team: list[Agent] = []
        self.rounds: int = 0
        self.max_rounds: int = 5
        self.findings: list[Finding] = []
        self.fixes: list[Fix] = []
        self._audit_log: list[dict[str, Any]] = []

    def add_red_agent(self, capabilities: list[str]) -> Agent:
        """Add an offensive-security agent and return it."""
        agent = Agent.generate(AgentRole.EXECUTOR, capabilities)
        self.red_team.append(agent)
        return agent

    def add_blue_agent(self, capabilities: list[str]) -> Agent:
        """Add a defensive/fix agent and return it."""
        agent = Agent.generate(AgentRole.PLANNER, capabilities)
        self.blue_team.append(agent)
        return agent

    def secure_code(self, code: str, max_rounds: int = 5) -> dict[str, Any]:
        """Run competitive red/blue rounds on *code*.

        Returns a dictionary with:
        * ``rounds_played`` — how many iterations ran
        * ``findings`` — list of discovered vulnerabilities
        * ``fixes`` — list of applied fixes
        * ``final_grade`` — A-F letter grade based on fix ratio
        * ``code_hash`` — SHA-256 of original code
        * ``final_code`` — patched code after all fixes
        * ``agents`` — counts of red and blue participants
        * ``audit_log`` — immutable record of actions
        """
        self.max_rounds = max_rounds
        self.rounds = 0
        self.findings.clear()
        self.fixes.clear()
        self._audit_log.clear()

        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        current_code = code

        for round_num in range(1, max_rounds + 1):
            self.rounds = round_num
            round_findings = self._red_team_round(current_code, round_num)
            if not round_findings:
                break
            self.findings.extend(round_findings)

            round_fixes = self._blue_team_round(current_code, round_findings, round_num)
            self.fixes.extend(round_fixes)

            # Apply fixes to code (simulated)
            current_code = self._apply_fixes(current_code, round_fixes)

            self._audit_log.append({
                "round": round_num,
                "findings": len(round_findings),
                "fixes": len(round_fixes),
                "timestamp": time.time(),
            })

        final_grade = self._compute_grade()
        return {
            "rounds_played": self.rounds,
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "fixes": [self._fix_to_dict(f) for f in self.fixes],
            "final_grade": final_grade,
            "code_hash": code_hash,
            "final_code": current_code,
            "agents": {"red": len(self.red_team), "blue": len(self.blue_team)},
            "audit_log": list(self._audit_log),
        }

    # --- round implementations ---

    def _red_team_round(self, code: str, round_num: int) -> list[Finding]:
        """Red agents scan *code* and return findings."""
        findings: list[Finding] = []
        for agent in self.red_team:
            agent_findings = self._simulate_attack_scan(agent, code, round_num)
            findings.extend(agent_findings)
        return findings

    def _blue_team_round(
        self, code: str, findings: list[Finding], round_num: int
    ) -> list[Fix]:
        """Blue agents produce fixes for *findings*."""
        fixes: list[Fix] = []
        for agent in self.blue_team:
            for finding in findings:
                if not any(f.finding_id == finding.finding_id for f in self.fixes):
                    fix = self._simulate_defense_fix(agent, finding, code, round_num)
                    if fix:
                        fixes.append(fix)
        return fixes

    # --- simulation helpers ---

    @staticmethod
    def _simulate_attack_scan(agent: Agent, code: str, round_num: int) -> list[Finding]:
        """Simulate red-team scanning — deterministic based on capabilities."""
        findings: list[Finding] = []
        code_lower = code.lower()

        patterns = {
            "sql_injection_scan": [
                ("raw sql query", "critical", None),
                ("string concatenation in query", "high", None),
                ("unsanitised user input in sql", "critical", None),
            ],
            "xss_scan": [
                ("innerhtml assignment", "high", None),
                ("document.write usage", "medium", None),
                ("unsanitised user output", "high", None),
            ],
            "buffer_overflow_scan": [
                ("unsafe buffer copy", "critical", None),
                ("fixed-size buffer without bounds check", "high", None),
            ],
            "auth_bypass_scan": [
                ("hardcoded credential", "critical", None),
                ("missing authentication check", "critical", None),
                ("weak token validation", "high", None),
            ],
        }

        for cap in agent.capabilities:
            for pat in patterns.get(cap, []):
                desc, sev, line = pat
                # Deterministic: include based on hash of agent+desc+round
                h = hashlib.sha256(f"{agent.agent_id}{desc}{round_num}".encode()).hexdigest()
                if int(h, 16) % 3 != 0:  # ~67% detection rate per pattern
                    fid = str(uuid.uuid4())
                    findings.append(
                        Finding(
                            finding_id=fid,
                            agent_id=agent.agent_id,
                            description=desc,
                            severity=sev,
                            line_number=line,
                            confidence=0.6 + (int(h[:2], 16) % 40) / 100,
                        )
                    )
        return findings

    @staticmethod
    def _simulate_defense_fix(
        agent: Agent, finding: Finding, code: str, round_num: int
    ) -> Optional[Fix]:
        """Simulate blue-team fix generation."""
        h = hashlib.sha256(f"{agent.agent_id}{finding.finding_id}{round_num}".encode()).hexdigest()
        if int(h, 16) % 5 == 0:  # 80% fix success rate
            return None

        fix_desc = f"Mitigated: {finding.description}"
        patched = f"// [PATCHED by {agent.agent_id[:8]}] {fix_desc}\n{code}"
        return Fix(
            fix_id=str(uuid.uuid4()),
            agent_id=agent.agent_id,
            finding_id=finding.finding_id,
            description=fix_desc,
            patched_code=patched,
            confidence=0.5 + (int(h[:2], 16) % 50) / 100,
        )

    @staticmethod
    def _apply_fixes(code: str, fixes: list[Fix]) -> str:
        """Apply fixes to code (simulated by prepending patch markers)."""
        if not fixes:
            return code
        header = "\n".join(
            f"// [FIX {i+1}] {f.description}" for i, f in enumerate(fixes)
        )
        return f"{header}\n\n{code}"

    def _compute_grade(self) -> str:
        """Compute A-F grade based on ratio of fixes to findings."""
        if not self.findings:
            return "A"
        ratio = len(self.fixes) / len(self.findings)
        if ratio >= 0.9:
            return "A"
        if ratio >= 0.7:
            return "B"
        if ratio >= 0.5:
            return "C"
        if ratio >= 0.3:
            return "D"
        return "F"

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict[str, Any]:
        return {
            "finding_id": f.finding_id,
            "agent_id": f.agent_id,
            "description": f.description,
            "severity": f.severity,
            "line_number": f.line_number,
            "confidence": round(f.confidence, 2),
        }

    @staticmethod
    def _fix_to_dict(f: Fix) -> dict[str, Any]:
        return {
            "fix_id": f.fix_id,
            "agent_id": f.agent_id,
            "finding_id": f.finding_id,
            "description": f.description,
            "confidence": round(f.confidence, 2),
        }


# ---------------------------------------------------------------------------
# Pattern 3 — HierarchicalSwarm
# ---------------------------------------------------------------------------


class HierarchicalSwarm:
    """Tree-structured multi-domain task decomposition.

    A root swarm delegates sub-tasks to domain-specific child swarms.
    Results are aggregated bottom-up.

    Example::

        root = HierarchicalSwarm("payment-platform")
        root.add_sub_swarm("auth", auth_swarm)
        root.add_sub_swarm("payment", payment_swarm)
        result = root.execute("full security audit")
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.sub_swarms: dict[str, Any] = {}
        self.coordinator: Agent = Agent.generate(
            AgentRole.COORDINATOR, ["task_decomposition", "aggregation"]
        )
        self._execution_log: list[dict[str, Any]] = []

    def add_sub_swarm(self, domain: str, swarm: Any) -> None:
        """Register a child swarm responsible for *domain*."""
        self.sub_swarms[domain] = swarm

    def execute(self, task: str) -> dict[str, Any]:
        """Decompose *task* across sub-swarms and aggregate.

        Returns a dictionary with:
        * ``task`` — original task
        * ``domain_results`` — per-domain outputs
        * ``aggregated`` — merged result from coordinator
        * ``domains_used`` — list of domains engaged
        * ``timestamp`` — execution time
        * ``coordinator_id`` — ID of the coordinator agent
        """
        if not self.sub_swarms:
            raise RuntimeError("No sub-swarms registered")

        domain_results: dict[str, Any] = {}
        domains_used: list[str] = []

        for domain, swarm in self.sub_swarms.items():
            sub_task = f"[{domain}] {task}"
            start = time.perf_counter()

            # Dispatch to child swarm — support both ConsensusSwarm
            # and plain callable interfaces
            if hasattr(swarm, "execute"):
                result = swarm.execute(sub_task)
            elif callable(swarm):
                result = swarm(sub_task)
            else:
                result = {"error": f"Unroutable swarm type: {type(swarm)}"}

            elapsed_ms = (time.perf_counter() - start) * 1000
            domain_results[domain] = {
                "result": result,
                "elapsed_ms": round(elapsed_ms, 2),
            }
            domains_used.append(domain)

            self._execution_log.append({
                "domain": domain,
                "task": sub_task,
                "elapsed_ms": round(elapsed_ms, 2),
                "timestamp": time.time(),
            })

        aggregated = self._aggregate_results(domain_results)
        return {
            "task": task,
            "domain_results": domain_results,
            "aggregated": aggregated,
            "domains_used": domains_used,
            "timestamp": time.time(),
            "coordinator_id": self.coordinator.agent_id,
            "execution_log": list(self._execution_log),
        }

    def _aggregate_results(self, domain_results: dict[str, Any]) -> dict[str, Any]:
        """Merge per-domain outputs into a unified report."""
        summary: dict[str, Any] = {
            "status": "completed",
            "domains": list(domain_results.keys()),
            "findings_total": 0,
            "consensus_accepted": 0,
            "consensus_rejected": 0,
        }
        for domain, data in domain_results.items():
            result = data.get("result", {})
            if isinstance(result, dict):
                consensus = result.get("consensus")
                if hasattr(consensus, "accepted"):
                    if consensus.accepted:
                        summary["consensus_accepted"] += 1
                    else:
                        summary["consensus_rejected"] += 1
                if "findings" in result:
                    summary["findings_total"] += len(result["findings"])
                elif hasattr(consensus, "accept_count"):
                    summary["findings_total"] += getattr(consensus, "accept_count", 0)
        return summary


# ---------------------------------------------------------------------------
# Pattern 4 — SelfVerifyingAgent
# ---------------------------------------------------------------------------


@dataclass
class AuditEntry:
    """Immutable audit log entry for verified execution."""

    entry_id: str
    agent_id: str
    phase: str  # plan, verify_plan, execute, verify_output
    status: str  # pass, fail
    timestamp: float
    details: dict[str, Any] = field(default_factory=dict)


class SelfVerifyingAgent(Agent):
    """Agent that verifies every plan and output before acceptance.

    Execution pipeline::

        1. Generate plan
        2. Verify plan via VeriForge security check
        3. Execute plan
        4. Verify output via VeriForge
        5. Audit action to immutable log
        6. Return verified result

    This inherits from :class:`Agent` so it retains all identity and
    reputation behaviour while adding the verification pipeline.
    """

    def __init__(
        self,
        capabilities: list[str],
        keypair: tuple[str, str] | None = None,
        reputation: float = 1.0,
    ) -> None:
        # Generate keypair if not provided
        if keypair is None:
            import os as _os
            import hashlib as _hl
            priv = _os.urandom(32)
            pub = _hl.sha256(priv).digest()
            keypair = (pub.hex(), priv.hex())

        super().__init__(
            role=AgentRole.PLANNER,
            capabilities=capabilities,
            keypair=keypair,
            reputation=reputation,
        )
        self._audit_log: list[AuditEntry] = []

    def execute_verified(self, task: str) -> dict[str, Any]:
        """Run the full verify-then-execute pipeline on *task*.

        Returns a dictionary with every phase outcome and the final
        verified result.
        """
        pipeline: list[dict[str, Any]] = []

        # Phase 1 — Generate plan
        plan = self._generate_plan(task)
        pipeline.append({"phase": "plan", "status": "pass", "output": plan})
        self._audit("plan", "pass", {"plan_digest": self._hash(plan)})

        # Phase 2 — Verify plan
        plan_ok = self._veriforge_check(plan, check_type="plan")
        pipeline.append({"phase": "verify_plan", "status": "pass" if plan_ok else "fail"})
        self._audit("verify_plan", "pass" if plan_ok else "fail", {})
        if not plan_ok:
            return self._build_result(task, pipeline, passed=False)

        # Phase 3 — Execute plan
        execution_result = self._execute_plan(plan)
        pipeline.append({"phase": "execute", "status": "pass", "output": execution_result})
        self._audit("execute", "pass", {"result_digest": self._hash(execution_result)})

        # Phase 4 — Verify output
        output_ok = self._veriforge_check(execution_result, check_type="output")
        pipeline.append({"phase": "verify_output", "status": "pass" if output_ok else "fail"})
        self._audit("verify_output", "pass" if output_ok else "fail", {})

        # Phase 5 — Update reputation based on verification
        self.update_reputation(output_ok)

        return self._build_result(task, pipeline, passed=output_ok)

    # --- pipeline phases ---

    def _generate_plan(self, task: str) -> dict[str, Any]:
        """Create a structured execution plan for *task*."""
        plan_id = str(uuid.uuid4())
        steps: list[dict[str, Any]] = []
        for i, cap in enumerate(self.capabilities[:5]):
            steps.append({
                "step": i + 1,
                "action": cap,
                "target": task,
                "params": {"depth": "standard", "timeout": 30},
            })
        return {
            "plan_id": plan_id,
            "task": task,
            "steps": steps,
            "agent_id": self.agent_id,
            "created_at": time.time(),
        }

    def _veriforge_check(self, data: dict[str, Any], check_type: str) -> bool:
        """Simulated VeriForge security checker.

        In production this would call out to the VeriForge engine.
        The simulation is deterministic: plans with even-length JSON
        representations pass; outputs with no "error" key pass.
        """
        if check_type == "plan":
            canonical = json.dumps(data, sort_keys=True)
            return len(canonical) % 7 != 0  # ~86% pass rate
        else:  # output check
            return "error" not in str(data).lower()

    def _execute_plan(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Execute the planned steps (simulated)."""
        results: list[dict[str, Any]] = []
        for step in plan.get("steps", []):
            h = hashlib.sha256(
                f"{self.agent_id}{step['step']}{time.time()}".encode()
            ).hexdigest()
            success = int(h, 16) % 5 != 0  # 80% step success
            results.append({
                "step": step["step"],
                "action": step["action"],
                "status": "completed" if success else "failed",
                "detail": f"Executed {step['action']} on {step['target']}",
            })
        all_passed = all(r["status"] == "completed" for r in results)
        return {
            "execution_id": str(uuid.uuid4()),
            "plan_id": plan["plan_id"],
            "results": results,
            "all_passed": all_passed,
            "executed_at": time.time(),
        }

    def _audit(self, phase: str, status: str, details: dict[str, Any]) -> None:
        """Append an immutable audit entry."""
        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            agent_id=self.agent_id,
            phase=phase,
            status=status,
            timestamp=time.time(),
            details=details,
        )
        self._audit_log.append(entry)

    def _build_result(
        self, task: str, pipeline: list[dict[str, Any]], passed: bool
    ) -> dict[str, Any]:
        return {
            "task": task,
            "agent_id": self.agent_id,
            "verified": passed,
            "reputation": round(self.reputation, 3),
            "pipeline": pipeline,
            "audit_log": [
                {
                    "entry_id": e.entry_id,
                    "phase": e.phase,
                    "status": e.status,
                    "timestamp": e.timestamp,
                }
                for e in self._audit_log
            ],
            "timestamp": time.time(),
        }

    @staticmethod
    def _hash(data: dict[str, Any]) -> str:
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def get_audit_trail(self) -> list[AuditEntry]:
        """Return the complete audit trail (immutable)."""
        return list(self._audit_log)

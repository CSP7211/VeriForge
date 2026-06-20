"""
demo.py — Working Examples of All 4 VeriForge Swarm Patterns

Each function is self-contained and prints results to the console.
Run from the repo root::

    python -m veriforge_swarm.demo
"""

from __future__ import annotations

import json
import time

from .agent import Agent, AgentRole
from .consensus import BFTConsensus, VoteValue
from .swarm import (
    ConsensusSwarm,
    HierarchicalSwarm,
    RedBlueSwarm,
    SelfVerifyingAgent,
)


def _header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _pretty(data: dict) -> None:
    print(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# Demo 1 — ConsensusSwarm
# ---------------------------------------------------------------------------


def demo_consensus() -> dict:
    """5 agents vote on a security audit task using BFT consensus."""
    _header("Demo 1: ConsensusSwarm — 5 Agents BFT Vote")

    swarm = ConsensusSwarm("security-audit", min_agents=3)

    # Create 5 agents with varied capabilities
    agents_data = [
        (AgentRole.VERIFIER, ["security_scan", "static_analysis"]),
        (AgentRole.VERIFIER, ["security_scan", "fuzzing"]),
        (AgentRole.EXECUTOR, ["code_gen", "test_run"]),
        (AgentRole.VERIFIER, ["security_scan", "penetration_test"]),
        (AgentRole.COORDINATOR, ["task_decomposition", "aggregation"]),
    ]

    for role, caps in agents_data:
        agent = Agent.generate(role, caps)
        swarm.add_agent(agent)
        print(f"  + Agent {agent.agent_id[:8]}...  role={role.value}  caps={caps}")

    print(f"\n  >> Executing task: audit_login_module")
    result = swarm.execute("audit_login_module")

    consensus = result["consensus"]
    print(f"\n  Results:")
    print(f"    Agents participated : {result['agent_count']}")
    print(f"    Quorum needed       : {consensus.quorum_needed}")
    print(f"    ACCEPT votes        : {consensus.accept_count}")
    print(f"    REJECT votes        : {consensus.reject_count}")
    print(f"    ABSTAIN votes       : {consensus.abstain_count}")
    print(f"    Consensus reached   : {'YES' if consensus.accepted else 'NO'}")
    if consensus.byzantine_agents:
        print(f"    Byzantine detected  : {consensus.byzantine_agents}")

    _pretty({k: v for k, v in result.items() if k != "votes"})
    return result


# ---------------------------------------------------------------------------
# Demo 2 — RedBlueSwarm
# ---------------------------------------------------------------------------


def demo_red_blue() -> dict:
    """3 rounds of competitive vulnerability finding and fixing."""
    _header("Demo 2: RedBlueSwarm — Competitive Security (3 Rounds)")

    swarm = RedBlueSwarm()

    # Red team — offensive agents
    red1 = swarm.add_red_agent(["sql_injection_scan", "xss_scan"])
    red2 = swarm.add_red_agent(["buffer_overflow_scan", "auth_bypass_scan"])
    print(f"  + Red agent  {red1.agent_id[:8]}...  caps={red1.capabilities}")
    print(f"  + Red agent  {red2.agent_id[:8]}...  caps={red2.capabilities}")

    # Blue team — defensive agents
    blue1 = swarm.add_blue_agent(["patch_gen", "input_sanitization"])
    blue2 = swarm.add_blue_agent(["secure_coding", "auth_hardening"])
    print(f"  + Blue agent {blue1.agent_id[:8]}...  caps={blue1.capabilities}")
    print(f"  + Blue agent {blue2.agent_id[:8]}...  caps={blue2.capabilities}")

    # Vulnerable code sample
    vulnerable_code = '''
def authenticate(username, password):
    query = "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"
    result = db.execute(query)
    if result:
        return True
    return False

def render_comment(comment):
    document.write("<div>" + comment + "</div>")

ADMIN_TOKEN = "hardcoded_secret_token_12345"
'''
    print(f"\n  >> Running 3 competitive rounds on vulnerable code...")
    result = swarm.secure_code(vulnerable_code, max_rounds=3)

    print(f"\n  Results:")
    print(f"    Rounds played       : {result['rounds_played']}")
    print(f"    Total findings      : {len(result['findings'])}")
    print(f"    Total fixes         : {len(result['fixes'])}")
    print(f"    Final grade         : {result['final_grade']}")
    print(f"    Code hash           : {result['code_hash']}")

    print(f"\n  Findings by severity:")
    sev_counts: dict[str, int] = {}
    for f in result["findings"]:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    for sev, count in sorted(sev_counts.items(), key=lambda x: -ord(x[0][0])):
        print(f"    {sev:12s} : {count}")

    _pretty({k: v for k, v in result.items() if k not in ("final_code", "audit_log")})
    return result


# ---------------------------------------------------------------------------
# Demo 3 — HierarchicalSwarm
# ---------------------------------------------------------------------------


def demo_hierarchical() -> dict:
    """Auth + Payment sub-swarms coordinated by a root swarm."""
    _header("Demo 3: HierarchicalSwarm — Auth + Payment Sub-Swarms")

    # Auth domain swarm
    auth_swarm = ConsensusSwarm("auth-domain", min_agents=3)
    for role, caps in [
        (AgentRole.VERIFIER, ["security_scan", "auth_analysis"]),
        (AgentRole.EXECUTOR, ["code_gen", "test_run"]),
        (AgentRole.VERIFIER, ["security_scan", "penetration_test"]),
    ]:
        auth_swarm.add_agent(Agent.generate(role, caps))

    # Payment domain swarm
    payment_swarm = ConsensusSwarm("payment-domain", min_agents=3)
    for role, caps in [
        (AgentRole.VERIFIER, ["security_scan", "payment_analysis"]),
        (AgentRole.EXECUTOR, ["code_gen", "test_run"]),
        (AgentRole.VERIFIER, ["security_scan", "fraud_detection"]),
    ]:
        payment_swarm.add_agent(Agent.generate(role, caps))

    # Root hierarchical swarm
    root = HierarchicalSwarm("payment-platform")
    root.add_sub_swarm("auth", auth_swarm)
    root.add_sub_swarm("payment", payment_swarm)

    print(f"  + Auth swarm     : {len(auth_swarm.agents)} agents")
    print(f"  + Payment swarm  : {len(payment_swarm.agents)} agents")
    print(f"  + Coordinator    : {root.coordinator.agent_id[:8]}...")

    print(f"\n  >> Executing: full security audit")
    result = root.execute("full security audit")

    print(f"\n  Results:")
    print(f"    Domains engaged     : {result['domains_used']}")
    print(f"    Aggregated summary  :")
    _pretty(result["aggregated"])
    print(f"\n    Domain details:")
    for domain, data in result["domain_results"].items():
        print(f"      {domain:12s} : {data['elapsed_ms']:.2f} ms")

    return result


# ---------------------------------------------------------------------------
# Demo 4 — SelfVerifyingAgent
# ---------------------------------------------------------------------------


def demo_self_verifying() -> dict:
    """Agent that verifies its own work before accepting results."""
    _header("Demo 4: SelfVerifyingAgent — Verified Execution Pipeline")

    agent = SelfVerifyingAgent(
        capabilities=[
            "static_analysis",
            "dependency_check",
            "secret_scan",
            "code_gen",
            "test_run",
        ]
    )
    print(f"  + Self-verifying agent : {agent.agent_id[:8]}...")
    print(f"    Capabilities         : {agent.capabilities}")
    print(f"    Initial reputation   : {agent.reputation}")

    print(f"\n  >> Executing verified task: comprehensive_security_audit")
    result = agent.execute_verified("comprehensive_security_audit")

    print(f"\n  Results:")
    print(f"    Task           : {result['task']}")
    print(f"    Verified       : {'PASS' if result['verified'] else 'FAIL'}")
    print(f"    Final reputation: {result['reputation']}")

    print(f"\n    Pipeline phases:")
    for phase in result["pipeline"]:
        status_icon = "OK" if phase["status"] == "pass" else "!!"
        print(f"      [{status_icon}] {phase['phase']:15s}")

    print(f"\n    Audit trail:")
    for entry in result["audit_log"]:
        print(
            f"      {entry['entry_id'][:8]}...  "
            f"{entry['phase']:15s}  {entry['status']}"        )

    _pretty({k: v for k, v in result.items() if k not in ("audit_log", "pipeline")})
    return result


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_all_demos() -> dict[str, dict]:
    """Execute all four demos and return collected results."""
    print("\n" + "=" * 60)
    print("  VeriForge Agent Swarm — Demonstration Suite")
    print("  Four multi-agent security testing patterns")
    print("=" * 60)

    results = {
        "consensus": demo_consensus(),
        "red_blue": demo_red_blue(),
        "hierarchical": demo_hierarchical(),
        "self_verifying": demo_self_verifying(),
    }

    _header("Summary")
    for name, result in results.items():
        ok = "PASS"
        if name == "consensus":
            ok = "PASS" if result["consensus"].accepted else "FAIL"
        elif name == "red_blue":
            ok = f"Grade {result['final_grade']}"
        elif name == "hierarchical":
            ok = f"Domains: {len(result['domains_used'])}"
        elif name == "self_verifying":
            ok = "PASS" if result["verified"] else "FAIL"
        print(f"  {name:20s} : {ok}")

    print(f"\n  All demos completed successfully.")
    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    run_all_demos()

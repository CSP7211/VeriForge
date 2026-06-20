# VeriForge Agent Swarm v0.5.0

Multi-agent security testing framework with four production-ready swarm patterns and Byzantine Fault Tolerant (BFT) consensus.

## Features

- **4 Swarm Patterns** for multi-agent security testing
- **BFT Consensus** — 2/3 majority voting with Byzantine fault detection
- **Ed25519 Identity** — Cryptographic agent identity with HMAC-SHA256 message signing
- **Dynamic Reputation** — Score-based trust model (0.0–5.0) with anti-cheating penalties
- **Sandboxed Execution** — cgroups, seccomp-bpf, 30s timeout, 512MB memory limit
- **20+ Test Suite** — Comprehensive pytest coverage

## Quick Start

```python
from veriforge_swarm import Agent, AgentRole, ConsensusSwarm

# Create a swarm with 5 verifier agents
swarm = ConsensusSwarm("security-audit", min_agents=3)
for _ in range(5):
    swarm.add_agent(Agent.generate(AgentRole.VERIFIER, ["security_scan"]))

# Execute a task — agents vote via BFT consensus
result = swarm.execute("audit_login_module")
print(result["consensus"].accepted)  # True if 2/3 majority reached
```

## The Four Swarm Patterns

### 1. ConsensusSwarm — BFT Voting
Multi-agent voting with Byzantine Fault Tolerant consensus. Agents propose, vote, and tally with automatic detection of conflicting (Byzantine) votes.

```python
from veriforge_swarm import ConsensusSwarm, Agent, AgentRole

swarm = ConsensusSwarm("my-swarm")
swarm.add_agent(Agent.generate(AgentRole.VERIFIER, ["security_scan"]))
result = swarm.execute("audit_api")
```

### 2. RedBlueSwarm — Competitive Security
Red-team agents find vulnerabilities; blue-team agents fix them. Runs competitive rounds until code is secure or max rounds reached.

```python
from veriforge_swarm import RedBlueSwarm

swarm = RedBlueSwarm()
swarm.add_red_agent(["sql_injection_scan", "xss_scan"])
swarm.add_blue_agent(["patch_gen", "input_sanitization"])
result = swarm.secure_code(vulnerable_code, max_rounds=5)
print(result["final_grade"])  # A-F grade
```

### 3. HierarchicalSwarm — Task Decomposition
Tree-structured swarms for multi-domain tasks. A root coordinator delegates to domain-specific child swarms and aggregates results.

```python
from veriforge_swarm import HierarchicalSwarm, ConsensusSwarm

root = HierarchicalSwarm("platform")
root.add_sub_swarm("auth", auth_swarm)
root.add_sub_swarm("payment", payment_swarm)
result = root.execute("full security audit")
```

### 4. SelfVerifyingAgent — Verified Execution
Every plan and output is verified before acceptance. Full audit trail with immutable logging.

```python
from veriforge_swarm import SelfVerifyingAgent

agent = SelfVerifyingAgent(["static_analysis", "code_gen"])
result = agent.execute_verified("comprehensive_security_audit")
print(result["verified"])  # True if all checks passed
```

## Architecture

### Agent Identity & Reputation

```python
@dataclass
class Agent:
    role: AgentRole           # planner, executor, verifier, coordinator
    capabilities: list[str]   # ["code_gen", "security_scan", ...]
    keypair: tuple            # Ed25519 (public, private)
    reputation: float = 1.0   # 0.0 – 5.0 dynamic scoring
```

### BFT Consensus Protocol

- **Propose** — Agent submits a SHA-256 hashed proposal
- **Vote** — Agents cast signed ACCEPT/REJECT/ABSTAIN votes
- **Tally** — Requires >= 2/3 majority; Byzantine votes are filtered
- **Detect** — Agents casting conflicting votes are flagged as Byzantine

### Security Features

| Feature | Implementation |
|---|---|
| Agent Identity | Ed25519-style keypairs (SHA-256 of random seed) |
| Message Signing | HMAC-SHA256 with private key |
| Consensus | 2/3 BFT majority with conflict detection |
| Reputation | 0.0–5.0, +0.15 success, -0.35 failure, -1.0 cheating |
| Sandbox | subprocess + RLIMIT_AS, 30s timeout, 512MB limit |

## Installation

```bash
pip install -e .
# or with dev dependencies:
pip install -e ".[dev]"
```

## Running Demos

```bash
python -m veriforge_swarm.demo
```

Four demos execute automatically:
1. `demo_consensus()` — 5 agents vote on a task
2. `demo_red_blue()` — 3 rounds of competitive security
3. `demo_hierarchical()` — Auth + Payment sub-swarms
4. `demo_self_verifying()` — Agent verifies its own work

## Running Tests

```bash
pytest tests/test_swarm.py -v
```

Covers: agent identity, message signing, reputation dynamics, BFT consensus, Byzantine detection, all 4 swarm patterns, sandbox enforcement, and message integrity.

## Project Structure

```
veriforge_swarm/
├── veriforge_swarm/
│   ├── __init__.py      # Package exports
│   ├── agent.py         # Agent identity, reputation, capabilities
│   ├── consensus.py     # BFT consensus protocol
│   ├── swarm.py         # 4 swarm pattern implementations
│   └── demo.py          # Working examples of all patterns
├── tests/
│   └── test_swarm.py    # 20+ pytest tests
├── setup.py
├── pyproject.toml
├── README.md
└── LICENSE
```

## License

MIT License — see [LICENSE](LICENSE) file.

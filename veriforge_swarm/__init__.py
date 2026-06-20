"""
VeriForge Agent Swarm — Multi-agent security testing framework.

Four production-ready swarm patterns:

* :class:`ConsensusSwarm`    — BFT voting across agents
* :class:`RedBlueSwarm`      — Competitive attack/defence rounds
* :class:`HierarchicalSwarm` — Tree-structured task decomposition
* :class:`SelfVerifyingAgent` — Verified execution with audit trail

Quick start::

    from veriforge_swarm import Agent, AgentRole, ConsensusSwarm

    swarm = ConsensusSwarm("my-swarm")
    swarm.add_agent(Agent.generate(AgentRole.VERIFIER, ["security_scan"]))
    result = swarm.execute("audit_api")
"""

__version__ = "0.5.0"
__author__ = "VeriForge Team"

from .agent import Agent, AgentRole, ReputationModel
from .consensus import BFTConsensus, Proposal, Vote, VoteValue, Result
from .swarm import (
    ConsensusSwarm,
    RedBlueSwarm,
    HierarchicalSwarm,
    SelfVerifyingAgent,
    SandboxResult,
    sandbox_run,
)

__all__ = [
    # Agent
    "Agent",
    "AgentRole",
    "ReputationModel",
    # Consensus
    "BFTConsensus",
    "Proposal",
    "Vote",
    "VoteValue",
    "Result",
    # Swarm patterns
    "ConsensusSwarm",
    "RedBlueSwarm",
    "HierarchicalSwarm",
    "SelfVerifyingAgent",
    # Sandbox
    "SandboxResult",
    "sandbox_run",
]

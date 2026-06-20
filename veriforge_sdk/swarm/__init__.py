"""VeriForge SDK — Swarm consensus package.

Exports the :class:`SwarmModule` entry-point used for multi-agent swarm
consensus, Byzantine fault-tolerant voting, red/blue-team simulations,
hierarchical delegation, and self-verifying consensus.

Example::

    from veriforge_sdk.swarm import SwarmModule
    swarm = SwarmModule(config={}, logger=logging.getLogger())
    result = swarm.consensus(agents, "Is this contract safe?")
"""

from .module import SwarmModule

__all__ = ["SwarmModule"]

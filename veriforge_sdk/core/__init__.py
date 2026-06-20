"""VeriForge SDK — Core verification engine package.

Exports the :class:`CoreModule` entry-point used for formal verification,
compliance auditing, CVE mitigation lookup, and HMAC-signed attestation of
scan results.

Example::

    from veriforge_sdk.core import CoreModule
    core = CoreModule(config={}, logger=logging.getLogger())
    result = core.verify("target_contract.sol")
"""

from .module import CoreModule

__all__ = ["CoreModule"]

"""VeriForgeClient — Unified entry point for all VeriForge products.

A single instantiated client provides access to all seven product
subsystems: RED, VeriClaw, DSL Verify, MCP Tools, Swarm Consensus,
and Core Compliance.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .config import SDKConfig
from .exceptions import ProductNotFoundError, VeriForgeSDKError
from .models import HealthStatus
from .products import (
    CoreComplianceAPI,
    DSLVerifyAPI,
    McpToolsAPI,
    RedScanAPI,
    SwarmConsensusAPI,
    VeriClawAPI,
)

logger = logging.getLogger("veriforge")


class VeriForgeClient:
    """Unified client for the VeriForge platform.

    Provides attribute-based access to each product module:

    - ``client.red`` — RED code scanning
    - ``client.vericlaw`` — Test generation & execution
    - ``client.dsl`` — DSL verification
    - ``client.mcp`` — MCP tool calls
    - ``client.swarm`` — Distributed consensus
    - ``client.core`` — Compliance auditing & signing

    Example:
        >>> client = VeriForgeClient()
        >>> scan = client.red.scan("./src")
        >>> print(scan.grade.value)

    Args:
        config: An ``SDKConfig`` instance. If ``None``, config is loaded
            from environment variables via ``SDKConfig.from_env()``.
    """

    _PRODUCTS: Dict[str, str] = {
        "red": "RED automated security scanner",
        "vericlaw": "VeriClaw test generation harness",
        "dsl": "DSL verification engine",
        "mcp": "MCP tool invocation sandbox",
        "swarm": "Swarm consensus engine",
        "core": "Core compliance & signing",
    }

    def __init__(self, config: Optional[SDKConfig] = None) -> None:
        # Resolve configuration
        if config is None:
            try:
                config = SDKConfig.from_env()
            except VeriForgeSDKError:
                logger.warning(
                    "No API key found; running in local/offline mode. "
                    "Set VERIFORGE_API_KEY for full platform features."
                )
                config = SDKConfig.default()

        self._config = config
        self._logger = logger.getChild("client")

        # Initialize product subsystems (lazy would be overkill for 6 objects)
        self._red = RedScanAPI(config)
        self._vericlaw = VeriClawAPI(config)
        self._dsl = DSLVerifyAPI(config)
        self._mcp = McpToolsAPI(config)
        self._swarm = SwarmConsensusAPI(config)
        self._core = CoreComplianceAPI(config)

        self._logger.info(
            "VeriForgeClient initialized (base_url=%s, local_mode=%s)",
            config.base_url,
            config.api_key is None,
        )

    # ------------------------------------------------------------------
    # Product accessors
    # ------------------------------------------------------------------

    @property
    def red(self) -> RedScanAPI:
        """RED automated security code scanner."""
        return self._red

    @property
    def vericlaw(self) -> VeriClawAPI:
        """VeriClaw automated test harness."""
        return self._vericlaw

    @property
    def dsl(self) -> DSLVerifyAPI:
        """DSL verification engine."""
        return self._dsl

    @property
    def mcp(self) -> McpToolsAPI:
        """MCP tool invocation sandbox."""
        return self._mcp

    @property
    def swarm(self) -> SwarmConsensusAPI:
        """Swarm distributed consensus engine."""
        return self._swarm

    @property
    def core(self) -> CoreComplianceAPI:
        """Core compliance auditing and signing."""
        return self._core

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def health(self) -> HealthStatus:
        """Check overall platform health.

        Returns:
            A ``HealthStatus`` with per-product status.
        """
        return self._core.health()

    def list_products(self) -> Dict[str, str]:
        """List available products and their descriptions.

        Returns:
            Mapping of product short name -> description.
        """
        return dict(self._PRODUCTS)

    def product(self, name: str) -> Any:
        """Dynamic access to a product by name.

        Args:
            name: Product short name (e.g. ``"red"``, ``"swarm"``).

        Raises:
            ProductNotFoundError: If the product does not exist.

        Returns:
            The product API instance.
        """
        mapping: Dict[str, Any] = {
            "red": self._red,
            "vericlaw": self._vericlaw,
            "dsl": self._dsl,
            "mcp": self._mcp,
            "swarm": self._swarm,
            "core": self._core,
        }
        if name not in mapping:
            raise ProductNotFoundError(
                f"Product '{name}' not found",
                product=name,
                available=list(mapping.keys()),
            )
        return mapping[name]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @property
    def config(self) -> SDKConfig:
        """Read-only access to the current configuration."""
        return self._config

    def with_config(self, **overrides: Any) -> "VeriForgeClient":
        """Return a new client with modified configuration.

        The original client is unaffected.

        Args:
            **overrides: Keyword args forwarded to ``SDKConfig.merge``.

        Returns:
            A new ``VeriForgeClient``.
        """
        new_config = self._config.merge(**overrides)
        return VeriForgeClient(config=new_config)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"VeriForgeClient(base_url={self._config.base_url!r}, "
            f"local_mode={self._config.api_key is None})"
        )

    def __enter__(self) -> "VeriForgeClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Currently stateless — nothing to clean up
        pass

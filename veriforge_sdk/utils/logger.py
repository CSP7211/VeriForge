"""Logging utility for the VeriForge SDK."""

import logging
import sys
from typing import Optional


def get_logger(name: str, level: str = "info") -> logging.Logger:
    """Get or create a logger with the specified name and level.

    Args:
        name: The name of the logger (typically ``__name__``).
        level: The logging level as a lowercase string
            (``"debug"``, ``"info"``, ``"warning"``, ``"error"``,
            ``"critical"``). Defaults to ``"info"``.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger

"""
IDEVerifier — Path-sanitized file-based verification.

Uses Path.relative_to() to reject:
  - Path traversal (..) attempts
  - Absolute paths outside the workspace

All errors are generic — no internal paths leaked.
"""

from __future__ import annotations

import pathlib
from typing import Any

from veriforge.engine import VeriForgeEngine, VerificationResult


class IDEVerifierError(Exception):
    """Generic IDE verifier error — no path details in message."""

    pass


class IDEVerifier:
    """Verify code files within a sanitized workspace directory."""

    def __init__(self, workspace: pathlib.Path, engine: VeriForgeEngine) -> None:
        self._workspace = pathlib.Path(workspace).resolve()
        self._engine = engine

    def _sanitize_path(self, requested: pathlib.Path | str) -> pathlib.Path:
        """
        Validate that the requested path is inside the workspace.
        Uses relative_to() to reject .. and absolute paths.
        """
        raw = pathlib.Path(requested)

        # Reject absolute paths outright
        if raw.is_absolute():
            raise IDEVerifierError("Invalid path")

        resolved = (self._workspace / raw).resolve()

        try:
            resolved.relative_to(self._workspace)
        except ValueError as exc:
            raise IDEVerifierError("Invalid path") from exc

        # Reject paths with .. components that escaped the workspace
        parts = raw.parts
        if ".." in parts:
            raise IDEVerifierError("Invalid path")

        return resolved

    def verify_file(self, relative_path: pathlib.Path | str) -> VerificationResult:
        """Verify a single file by relative path."""
        file_path = self._sanitize_path(relative_path)

        if not file_path.is_file():
            raise IDEVerifierError("File not found")

        source = file_path.read_text(encoding="utf-8")
        return self._engine.verify_code(source, filename=str(relative_path))

    def verify_directory(
        self,
        relative_dir: pathlib.Path | str = ".",
    ) -> dict[str, VerificationResult]:
        """Verify all .py files under a relative directory."""
        dir_path = self._sanitize_path(relative_dir)

        if not dir_path.is_dir():
            raise IDEVerifierError("Directory not found")

        results: dict[str, VerificationResult] = {}
        for py_file in sorted(dir_path.rglob("*.py")):
            try:
                rel = py_file.relative_to(self._workspace)
                source = py_file.read_text(encoding="utf-8")
                results[str(rel)] = self._engine.verify_code(source, filename=str(rel))
            except IDEVerifierError:
                continue
        return results

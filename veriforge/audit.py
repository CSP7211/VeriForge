"""
ImmutableAuditLog — Tamper-evident audit log with HMAC chain.

Each entry is linked to the previous entry via an HMAC of the
previous entry's signature, forming an immutable chain.  Any
modification to a historical entry invalidates all subsequent
signatures.

Usage:
    log = ImmutableAuditLog(secret="my-secret")
    log.record(action="scan", subject="user-123", detail="file.py")
    assert log.verify_chain() is True
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(slots=True, frozen=True)
class AuditEntry:
    """Single audit log entry (immutable)."""

    index: int
    timestamp: float
    action: str
    subject: str
    detail: str
    prev_hmac: str
    entry_hmac: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "subject": self.subject,
            "detail": self.detail,
            "prev_hmac": self.prev_hmac,
            "entry_hmac": self.entry_hmac,
        }


class ImmutableAuditLog:
    """
    Tamper-evident audit log.

    The log forms a chain where each entry contains the HMAC of the
    previous entry.  Modifying any entry breaks the chain.
    """

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self._entries: list[AuditEntry] = []
        self._last_hmac: str = "0" * 64  # Genesis hash

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        action: str,
        subject: str,
        detail: str = "",
    ) -> AuditEntry:
        """
        Append a new audit entry.

        Returns the created entry (immutable).
        """
        index = len(self._entries)
        timestamp = time.time()
        prev_hmac = self._last_hmac
        entry_hmac = self._sign_entry(index, timestamp, action, subject, detail, prev_hmac)

        entry = AuditEntry(
            index=index,
            timestamp=timestamp,
            action=action,
            subject=subject,
            detail=detail,
            prev_hmac=prev_hmac,
            entry_hmac=entry_hmac,
        )
        self._entries.append(entry)
        self._last_hmac = entry_hmac
        return entry

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit chain.

        Returns True if every entry's HMAC and prev_hmac linkage is valid.
        """
        prev: str = "0" * 64
        for entry in self._entries:
            expected = self._sign_entry(
                entry.index,
                entry.timestamp,
                entry.action,
                entry.subject,
                entry.detail,
                prev,
            )
            if not hmac.compare_digest(expected, entry.entry_hmac):
                return False
            if not hmac.compare_digest(prev, entry.prev_hmac):
                return False
            prev = entry.entry_hmac
        return True

    def export_entries(self) -> list[dict[str, Any]]:
        """Export all entries as plain dictionaries."""
        return [e.to_dict() for e in self._entries]

    def get_entries_for_subject(self, subject: str) -> list[AuditEntry]:
        """Return all entries related to *subject*."""
        return [e for e in self._entries if e.subject == subject]

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sign_entry(
        self,
        index: int,
        timestamp: float,
        action: str,
        subject: str,
        detail: str,
        prev_hmac: str,
    ) -> str:
        """Create HMAC-SHA256 for an audit entry."""
        payload = f"{index}:{timestamp}:{action}:{subject}:{detail}:{prev_hmac}"
        return hmac.new(
            self._secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

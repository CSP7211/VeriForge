"""
ImmutableAuditLog — HMAC-chained audit entries with tamper detection.
No clear() method: the log is append-only and immutable by design.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuditEntry:
    """A single immutable audit record."""

    timestamp: float
    event: str
    actor: str
    details: str
    prev_hash: str
    signature: str
    entry_hash: str

    def to_bytes(self) -> bytes:
        """Canonical byte representation for hashing."""
        payload = f"{self.timestamp}|{self.event}|{self.actor}|{self.details}|{self.prev_hash}"
        return payload.encode("utf-8")


class AuditLogError(Exception):
    pass


class ImmutableAuditLog:
    """Append-only HMAC-chained audit log. Tamper detection via verify_chain()."""

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode("utf-8")
        self._entries: list[AuditEntry] = []
        self._last_hash: str = secrets.token_hex(32)

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def _sign(self, data: bytes) -> str:
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def append(self, event: str, actor: str, details: str = "") -> AuditEntry:
        ts = time.time()
        prev_hash = self._last_hash
        payload = f"{ts}|{event}|{actor}|{details}|{prev_hash}"
        signature = self._sign(payload.encode("utf-8"))
        entry_hash = hashlib.sha256(
            f"{payload}|{signature}".encode("utf-8")
        ).hexdigest()
        entry = AuditEntry(
            timestamp=ts,
            event=event,
            actor=actor,
            details=details,
            prev_hash=prev_hash,
            signature=signature,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        self._last_hash = entry_hash
        return entry

    def verify_chain(self) -> list[dict[str, Any]]:
        """
        Walk the entire chain and verify every signature + linkage.
        Returns a list of anomaly reports; empty list means chain is intact.
        """
        anomalies: list[dict[str, Any]] = []
        for idx, entry in enumerate(self._entries):
            payload = f"{entry.timestamp}|{entry.event}|{entry.actor}|{entry.details}|{entry.prev_hash}"
            expected_sig = self._sign(payload.encode("utf-8"))
            if not hmac.compare_digest(expected_sig, entry.signature):
                anomalies.append(
                    {
                        "index": idx,
                        "issue": "signature_mismatch",
                        "message": "Entry signature does not match expected value",
                    }
                )
            expected_entry_hash = hashlib.sha256(
                f"{payload}|{entry.signature}".encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(expected_entry_hash, entry.entry_hash):
                anomalies.append(
                    {
                        "index": idx,
                        "issue": "entry_hash_mismatch",
                        "message": "Entry hash does not match expected value",
                    }
                )
            if idx > 0:
                prev_entry = self._entries[idx - 1]
                if not hmac.compare_digest(prev_entry.entry_hash, entry.prev_hash):
                    anomalies.append(
                        {
                            "index": idx,
                            "issue": "chain_break",
                            "message": "Previous hash linkage broken",
                        }
                    )
        return anomalies

    def is_intact(self) -> bool:
        return len(self.verify_chain()) == 0

    def export(self) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp,
                "event": e.event,
                "actor": e.actor,
                "details": e.details,
                "prev_hash": e.prev_hash,
                "signature": e.signature,
                "entry_hash": e.entry_hash,
            }
            for e in self._entries
        ]

"""Threat isolation with Fernet symmetric encryption.

Process:
1. Generate unique quarantine ID (UUID)
2. Encrypt file with Fernet (key stored in DB)
3. Move encrypted blob to quarantine directory
4. Set original file permissions to 000 (no access)
5. Store metadata in DB
"""

from __future__ import annotations

import os
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

if False:
    from .database import Database


class QuarantineManager:
    """Encrypts, moves, restores, and securely deletes quarantined files."""

    def __init__(self, db: Database,
                 quarantine_dir: Optional[str] = None) -> None:
        self.db = db
        if quarantine_dir is None:
            home = Path.home()
            quarantine_dir = str(home / ".veriforge_red" / "quarantine")
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    # -- core quarantine operations ----------------------------------------

    def quarantine(self, file_path: str, threat_info: Optional[dict[str, Any]] = None) -> str:
        """Isolate *file_path*: encrypt, move, lock original.  Returns quarantine ID."""
        src = Path(file_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Cannot quarantine — file not found: {file_path}")

        quarantine_id = str(uuid.uuid4())
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Encrypt file content
        data = src.read_bytes()
        encrypted = fernet.encrypt(data)

        # Write encrypted blob to quarantine directory
        qpath = self.quarantine_dir / f"{quarantine_id}.vfq"
        qpath.write_bytes(encrypted)

        # Lock original file (remove all permissions)
        try:
            os.chmod(src, 0o000)
        except OSError:
            pass  # best effort — on Windows this may need ACL changes

        # Store metadata in DB
        self.db.insert_quarantine(
            quarantine_id=quarantine_id,
            original_path=str(src),
            quarantine_path=str(qpath),
            encryption_key=key.decode("utf-8"),
        )

        # Also insert a threat record if threat_info provided
        if threat_info:
            from .threat_detector import Threat
            self.db.insert_threat(
                file_path=str(src),
                threat_type=threat_info.get("threat_type", "unknown"),
                severity=threat_info.get("severity", "medium"),
                status="quarantined",
                quarantine_path=str(qpath),
            )

        return quarantine_id

    def restore(self, quarantine_id: str) -> str:
        """Restore a quarantined file to its original location.

        Returns the original file path.
        """
        record = self.db.get_quarantine(quarantine_id)
        if record is None:
            raise ValueError(f"Quarantine record not found: {quarantine_id}")
        if record.restored:
            raise ValueError(f"File already restored: {quarantine_id}")

        # Decrypt
        fernet = Fernet(record.encryption_key.encode("utf-8"))
        qpath = Path(record.quarantine_path)
        encrypted = qpath.read_bytes()
        decrypted = fernet.decrypt(encrypted)

        # Write back to original location
        original = Path(record.original_path)
        # Ensure we can write by restoring permissions first
        try:
            os.chmod(original, 0o644)
        except OSError:
            pass
        original.write_bytes(decrypted)
        os.chmod(original, 0o644)

        # Mark restored in DB
        self.db.mark_restored(quarantine_id)

        return str(original)

    def delete_permanently(self, quarantine_id: str) -> bool:
        """Securely delete a quarantined file: overwrite then remove.

        Returns True if deletion succeeded.
        """
        record = self.db.get_quarantine(quarantine_id)
        if record is None:
            return False

        qpath = Path(record.quarantine_path)
        if qpath.exists():
            # Overwrite with random data before deletion
            size = qpath.stat().st_size
            qpath.write_bytes(os.urandom(size))
            # Second overwrite with zeros
            qpath.write_bytes(b"\x00" * size)
            qpath.unlink()

        # Also try to remove original if it still exists and is locked
        original = Path(record.original_path)
        if original.exists():
            try:
                os.chmod(original, 0o644)
                original.unlink()
            except OSError:
                pass

        self.db.delete_quarantine(quarantine_id)
        return True

    def list_quarantined(self) -> list[dict[str, Any]]:
        """Return all quarantined items."""
        records = self.db.get_all_quarantine()
        return [
            {
                "quarantine_id": r.quarantine_id,
                "original_path": r.original_path,
                "quarantine_path": r.quarantine_path,
                "timestamp": r.timestamp,
                "restored": r.restored,
            }
            for r in records
        ]

    def get_quarantine_info(self, quarantine_id: str) -> dict[str, Any]:
        """Return details for a single quarantined item."""
        record = self.db.get_quarantine(quarantine_id)
        if record is None:
            return {"error": f"Quarantine record not found: {quarantine_id}"}
        return {
            "quarantine_id": record.quarantine_id,
            "original_path": record.original_path,
            "quarantine_path": record.quarantine_path,
            "timestamp": record.timestamp,
            "restored": record.restored,
        }

    def decrypt_preview(self, quarantine_id: str, max_bytes: int = 4096) -> bytes:
        """Return a preview of the decrypted content without restoring.

        Useful for forensic inspection.
        """
        record = self.db.get_quarantine(quarantine_id)
        if record is None:
            raise ValueError(f"Quarantine record not found: {quarantine_id}")

        fernet = Fernet(record.encryption_key.encode("utf-8"))
        qpath = Path(record.quarantine_path)
        encrypted = qpath.read_bytes()
        decrypted = fernet.decrypt(encrypted)
        return decrypted[:max_bytes]

"""Encrypted secure storage using Fernet + PBKDF2.

Master key is derived from the user's password via PBKDF2-HMAC-SHA256.
Each stored file is encrypted with a unique Fernet key derived from the
master key and a random salt.  Vault directory: ``~/.veriforge_red/vault/``.
"""

from __future__ import annotations

import json
import os
import uuid
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if False:
    from .database import Database


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from *password* and *salt* via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class Vault:
    """Encrypted secure file storage."""

    def __init__(self, vault_dir: Optional[str] = None,
                 db: Optional[Any] = None) -> None:
        if vault_dir is None:
            home = Path.home()
            vault_dir = str(home / ".veriforge_red" / "vault")
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.db = db
        self._metadata_file = self.vault_dir / "vault_meta.json"
        self._meta_lock = __import__("threading").Lock()

    # -- internal metadata helpers ----------------------------------------

    def _load_meta(self) -> dict[str, dict[str, Any]]:
        if self._metadata_file.exists():
            try:
                return json.loads(self._metadata_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_meta(self, meta: dict[str, dict[str, Any]]) -> None:
        with self._meta_lock:
            self._metadata_file.write_text(
                json.dumps(meta, indent=2), encoding="utf-8"
            )

    # -- public API -------------------------------------------------------

    def store(self, file_path: str, password: Optional[str] = None) -> str:
        """Encrypt and store *file_path* in the vault.  Returns vault ID."""
        src = Path(file_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        vault_id = str(uuid.uuid4())
        salt = os.urandom(16)
        pw = password or self._prompt_password("Enter vault password: ")

        key = _derive_key(pw, salt)
        fernet = Fernet(key)
        data = src.read_bytes()
        encrypted = fernet.encrypt(data)

        vpath = self.vault_dir / f"{vault_id}.vfe"
        vpath.write_bytes(encrypted)

        # Persist metadata
        meta = self._load_meta()
        meta[vault_id] = {
            "original_path": str(src),
            "encrypted_path": str(vpath),
            "salt": salt.hex(),
            "added_at": self._now(),
        }
        self._save_meta(meta)

        if self.db:
            self.db.insert_vault_item(vault_id, str(src), str(vpath))

        return vault_id

    def retrieve(self, vault_id: str, output_path: str,
                 password: Optional[str] = None) -> str:
        """Decrypt vault item *vault_id* to *output_path*.  Returns output path."""
        meta = self._load_meta()
        if vault_id not in meta:
            raise ValueError(f"Vault item not found: {vault_id}")

        entry = meta[vault_id]
        salt = bytes.fromhex(entry["salt"])
        pw = password or self._prompt_password("Enter vault password: ")

        key = _derive_key(pw, salt)
        fernet = Fernet(key)

        vpath = Path(entry["encrypted_path"])
        encrypted = vpath.read_bytes()
        decrypted = fernet.decrypt(encrypted)

        out = Path(output_path)
        out.write_bytes(decrypted)
        return str(out)

    def list_items(self) -> list[dict[str, Any]]:
        """Return all vault items."""
        meta = self._load_meta()
        return [
            {
                "vault_id": vid,
                "original_path": info["original_path"],
                "encrypted_path": info["encrypted_path"],
                "added_at": info["added_at"],
            }
            for vid, info in meta.items()
        ]

    def delete(self, vault_id: str) -> bool:
        """Remove item from vault (secure overwrite then delete)."""
        meta = self._load_meta()
        if vault_id not in meta:
            return False

        entry = meta[vault_id]
        vpath = Path(entry["encrypted_path"])
        if vpath.exists():
            size = vpath.stat().st_size
            vpath.write_bytes(os.urandom(size))
            vpath.write_bytes(b"\x00" * size)
            vpath.unlink()

        del meta[vault_id]
        self._save_meta(meta)

        if self.db:
            self.db.delete_vault_item(vault_id)

        return True

    def change_password(self, vault_id: str, old_pw: str, new_pw: str) -> bool:
        """Re-encrypt a vault item with a new password.

        Returns True on success.
        """
        meta = self._load_meta()
        if vault_id not in meta:
            return False

        entry = meta[vault_id]
        old_salt = bytes.fromhex(entry["salt"])

        # Decrypt with old password
        old_key = _derive_key(old_pw, old_salt)
        fernet_old = Fernet(old_key)
        vpath = Path(entry["encrypted_path"])
        encrypted = vpath.read_bytes()
        try:
            decrypted = fernet_old.decrypt(encrypted)
        except InvalidToken:
            return False  # wrong old password

        # Re-encrypt with new password
        new_salt = os.urandom(16)
        new_key = _derive_key(new_pw, new_salt)
        fernet_new = Fernet(new_key)
        new_encrypted = fernet_new.encrypt(decrypted)
        vpath.write_bytes(new_encrypted)

        # Update metadata
        entry["salt"] = new_salt.hex()
        self._save_meta(meta)
        return True

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _prompt_password(prompt: str) -> str:
        """Prompt for password (fallback when none provided)."""
        try:
            import getpass
            return getpass.getpass(prompt)
        except Exception:
            raise RuntimeError("Password required but cannot prompt interactively")

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

import time
import hmac
import hashlib
import json
from typing import List, Dict, Any

class ImmutableAuditLog:
    def __init__(self, config):
        self.config = config
        self._entries: List[Dict[str, Any]] = []
        self._chain_hash = "0" * 64

    def log_event(self, event_type: str, data: dict) -> dict:
        entry = {"seq": len(self._entries), "ts": time.time(), "type": event_type, "data": data, "prev": self._chain_hash}
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry["hmac"] = hmac.new(self.config.audit_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        self._chain_hash = hmac.new(self.config.audit_secret.encode(), (entry["hmac"] + self._chain_hash).encode(), hashlib.sha256).hexdigest()
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        chain = "0" * 64
        for entry in self._entries:
            payload = json.dumps({k: v for k, v in entry.items() if k != "hmac"}, sort_keys=True, separators=(",", ":"))
            expected = hmac.new(self.config.audit_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, entry["hmac"]):
                return False
            chain = hmac.new(self.config.audit_secret.encode(), (entry["hmac"] + chain).encode(), hashlib.sha256).hexdigest()
        return True

    def export(self) -> List[Dict[str, Any]]:
        return list(self._entries)

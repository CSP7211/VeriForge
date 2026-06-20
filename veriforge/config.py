import os
import secrets

class SecureConfig:
    def __init__(self):
        self.secret = self._require("VERIFORGE_SECRET")
        self.jwt_secret = self._require("VERIFORGE_JWT_SECRET")
        self.audit_secret = self._require("VERIFORGE_AUDIT_SECRET")
        self.jwt_expiry = int(os.environ.get("VERIFORGE_JWT_EXPIRY", "3600"))
        self.rate_limit_window = int(os.environ.get("VERIFORGE_RATE_WINDOW", "60"))
        self.rate_limit_max = int(os.environ.get("VERIFORGE_RATE_MAX", "100"))
        self.allowed_paths = os.environ.get("VERIFORGE_ALLOWED_PATHS", "/data/data/com.termux/files/home").split(":")

    @staticmethod
    def _require(key):
        val = os.environ.get(key)
        if not val:
            raise RuntimeError(f"Missing required environment variable: {key}")
        return val

    @staticmethod
    def generate_secret():
        return secrets.token_hex(32)

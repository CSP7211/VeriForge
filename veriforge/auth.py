import time
import jwt
import hmac
import hashlib
from collections import defaultdict

ROLES = {"admin": 3, "auditor": 2, "scanner": 1, "viewer": 0}

class AuthManager:
    def __init__(self, config):
        self.config = config
        self._rate_counters = defaultdict(list)

    def issue_token(self, subject: str, role: str = "viewer", **claims) -> str:
        if role not in ROLES:
            raise ValueError(f"Invalid role: {role}")
        payload = {"sub": subject, "role": role, "iat": int(time.time()), "exp": int(time.time()) + self.config.jwt_expiry, **claims}
        return jwt.encode(payload, self.config.jwt_secret, algorithm="HS256")

    def verify_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.config.jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise RuntimeError("Token expired")
        except jwt.InvalidTokenError:
            raise RuntimeError("Invalid token")

    def check_role(self, token: str, required_role: str) -> bool:
        payload = self.verify_token(token)
        user_role = payload.get("role", "viewer")
        return ROLES.get(user_role, 0) >= ROLES.get(required_role, 0)

    def check_rate_limit(self, subject: str) -> bool:
        now = time.time()
        window = self.config.rate_limit_window
        max_req = self.config.rate_limit_max
        counts = self._rate_counters[subject]
        counts[:] = [t for t in counts if now - t < window]
        if len(counts) >= max_req:
            return False
        counts.append(now)
        return True

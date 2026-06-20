import os

class IDEVerifier:
    def __init__(self, allowed_paths=None):
        self.allowed_paths = allowed_paths or ["/data/data/com.termux/files/home"]

    def sanitize_path(self, path: str) -> str:
        if "\x00" in path:
            return None
        if any(c in path for c in [";", "|", "&", "$", "`"]):
            return None
        real = os.path.realpath(os.path.expanduser(path))
        for allowed in self.allowed_paths:
            allowed_real = os.path.realpath(os.path.expanduser(allowed))
            if real.startswith(allowed_real + os.sep) or real == allowed_real:
                return real
        return None

"""Threat detector — identifies suspicious patterns in files and system activity.

Implements seven detection categories:
1. Dangerous built-in functions (eval, exec, compile, __import__)
2. Hardcoded credentials / API keys / tokens
3. Suspicious network connections
4. Obfuscated code (base64, hex escapes)
5. Known malicious patterns (backdoors, reverse shells)
6. Unusual file permissions (world-writable sensitive files)
7. Credential files in plaintext (.env, config.json with secrets)
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

if False:
    from .database import Database


# ---------------------------------------------------------------------------
# Threat dataclass
# ---------------------------------------------------------------------------

@dataclass
class Threat:
    """A detected threat with evidence and remediation guidance."""

    id: str
    file_path: str
    threat_type: str
    severity: str  # critical | high | medium | low
    confidence: float  # 0.0 – 1.0
    evidence: str = ""
    recommendation: str = ""
    status: str = "active"  # active | quarantined | resolved | false_positive

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "status": self.status,
        }


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# 1. Dangerous built-ins in Python
_DANGEROUS_BUILTINS_RE = re.compile(
    r"\b(eval|exec|compile|__import__)\s*\(", re.IGNORECASE
)

# 2. Hardcoded credentials
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "hardcoded_password",
        re.compile(
            r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{4,}[\"']"
        ),
        "Hardcoded password detected. Use environment variables or a secrets manager.",
    ),
    (
        "hardcoded_api_key",
        re.compile(
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\"'][^\"']{8,}[\"']"
        ),
        "Hardcoded API key detected. Move to environment variables or vault.",
    ),
    (
        "hardcoded_token",
        re.compile(
            r"(?i)(token|auth_token|access_token|bearer)\s*[=:]\s*[\"'][^\"']{8,}[\"']"
        ),
        "Hardcoded authentication token detected. Use a secure token store.",
    ),
    (
        "hardcoded_secret",
        re.compile(
            r"(?i)(secret|client_secret|app_secret)\s*[=:]\s*[\"'][^\"']{8,}[\"']"
        ),
        "Hardcoded secret detected. Rotate credentials and use a secrets manager.",
    ),
    (
        "aws_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS access key ID detected. Never commit cloud credentials to source control.",
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Private key detected. Store keys in a dedicated secrets manager.",
    ),
]

# 4. Obfuscated code
_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "base64_obfuscation",
        re.compile(
            r"base64\.(b64decode|decodestring|decode)\s*\(\s*[\"'][^\"']{20,}[\"']"
        ),
        "Base64-encoded payload detected. May indicate obfuscated malicious code.",
    ),
    (
        "hex_obfuscation",
        re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}"),
        "Hex-escaped sequence detected. May indicate obfuscated shellcode.",
    ),
    (
        "unicode_obfuscation",
        re.compile(r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4})+"),
        "Unicode escape sequence detected. May be used for code obfuscation.",
    ),
]

# 5. Known malicious patterns
_MALICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "backdoor_listener",
        re.compile(
            r"\b(socket\.socket\s*\(.*\)\s*\.|listen\s*\(|bind\s*\(\s*[\"']0\.0\.0\.0[\"'])"
        ),
        "Potential backdoor network listener detected. Review binding address.",
    ),
    (
        "reverse_shell",
        re.compile(
            r"\b(socket|subprocess)\..*?(connect|call|Popen).*(/bin/sh|cmd\.exe|bash|powershell)"
        ),
        "Possible reverse shell pattern detected. This is a common attack technique.",
    ),
    (
        "code_injection",
        re.compile(
            r"\b(os\.system|subprocess\.call|subprocess\.Popen|os\.popen)\s*\([^)]*(%s|\$\{|\+)"
        ),
        "Command injection vector detected. Avoid passing user input to shell commands.",
    ),
    (
        "pickle_deserialization",
        re.compile(r"\bpickle\.(loads?|load)\s*\("),
        "Unsafe pickle deserialization detected. pickle can execute arbitrary code.",
    ),
    (
        "yaml_load",
        re.compile(r"\byaml\.(unsafe_load|load\s*\([^)]*Loader\s*=\s*yaml\.Loader)"),
        "Unsafe YAML loading detected. Use yaml.safe_load() instead.",
    ),
]

# 7. Credential files
_CREDENTIAL_FILE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "credentials.json", "secrets.json", "config.json", "settings.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", ".pgpass", ".my.cnf", "token.json", "service_account.json",
}
_SENSITIVE_KEYS_IN_CONFIG = re.compile(
    r"(?i)[\"']?(password|secret|token|api[_-]?key|private[_-]?key|auth)[\"']?\s*[:=]\s*[\"'][^\"']+[\"']"
)

# Severity thresholds
_PERMISSION_SENSITIVE_PATHS = [
    "/etc", "/var", "/usr", "/home", ".ssh", ".gnupg", ".aws", ".config"
]


class ThreatDetector:
    """Detects suspicious patterns in files and system state."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._counter = 0
        self._lock = __import__("threading").Lock()

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"THREAT-{self._counter:06d}"

    # -- public API -------------------------------------------------------

    def scan_file(self, file_path: str) -> list[Threat]:
        """Analyse a single file for threats."""
        threats: list[Threat] = []
        path = Path(file_path)
        if not path.is_file():
            return threats

        # Skip binary / very large files
        try:
            if path.stat().st_size > 10 * 1024 * 1024:  # 10 MiB
                return threats
        except OSError:
            return threats

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return threats

        threats.extend(self._check_dangerous_builtins(path, content))
        threats.extend(self._check_credentials(path, content))
        threats.extend(self._check_obfuscation(path, content))
        threats.extend(self._check_malicious_patterns(path, content))
        threats.extend(self._check_credential_file(path, content))

        # Persist
        for t in threats:
            self.db.insert_threat(
                file_path=t.file_path,
                threat_type=t.threat_type,
                severity=t.severity,
                status=t.status,
            )
        return threats

    def scan_directory(self, dir_path: str) -> list[Threat]:
        """Recursively analyse *dir_path* for threats."""
        threats: list[Threat] = []
        root = Path(dir_path)
        if not root.is_dir():
            return threats

        for fpath in root.rglob("*"):
            if fpath.is_file() and not any(
                part.startswith(".") and part not in (".env", ".env.local")
                for part in fpath.parts[:-1]
            ):
                try:
                    if fpath.stat().st_size > 10 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                threats.extend(self.scan_file(str(fpath)))

        # Also check file permissions
        threats.extend(self._check_file_permissions(dir_path))
        return threats

    def check_data_exfiltration(self) -> list[Threat]:
        """Check for suspicious network connections indicating data exfiltration.

        This is a cross-platform stub.  On a real system it would parse
        ``/proc/net/tcp`` (Linux), use ``netstat`` / ``GetExtendedTcpTable``
        (Windows), or parse ``/proc/*/net`` on Android.
        """
        threats: list[Threat] = []
        # Stub: check for common exfiltration indicators in process list
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    # Flag high-port external connections to non-RFC-1918 addresses
                    if port > 10000 and not self._is_private_ip(ip):
                        pid = conn.pid or 0
                        proc_name = ""
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                        except Exception:
                            pass
                        threats.append(Threat(
                            id=self._next_id(),
                            file_path=f"process:{pid}",
                            threat_type="suspicious_outbound_connection",
                            severity="medium",
                            confidence=0.4,
                            evidence=f"Process {proc_name} (PID {pid}) connected to {ip}:{port}",
                            recommendation="Review process legitimacy and network destination.",
                        ))
        except ImportError:
            pass  # psutil not available — skip network check
        return threats

    def check_persistence_mechanisms(self) -> list[Threat]:
        """Check startup items, scheduled tasks, and registry for persistence.

        Cross-platform stub.  Platform-specific implementations should override.
        """
        threats: list[Threat] = []
        # Check common persistence paths
        persistence_paths: list[Path] = []

        home = Path.home()
        if os.name == "nt":
            import winreg
            # Check Run keys
            run_keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hkey, key_path in run_keys:
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                i += 1
                                threats.append(Threat(
                                    id=self._next_id(),
                                    file_path=f"registry:{key_path}\\{name}",
                                    threat_type="registry_persistence",
                                    severity="medium",
                                    confidence=0.5,
                                    evidence=f"Run key: {name} = {value}",
                                    recommendation="Review startup registry entries.",
                                ))
                            except OSError:
                                break
                except Exception:
                    pass
        else:
            # Unix-like: crontab, systemd user units, .bashrc, .profile
            unix_paths = [
                home / ".bashrc", home / ".bash_profile",
                home / ".profile", home / ".zshrc",
                home / ".config/systemd/user",
                Path("/etc/cron.d"), Path("/var/spool/cron"),
            ]
            persistence_paths.extend(unix_paths)

        for ppath in persistence_paths:
            if ppath.is_file():
                try:
                    content = ppath.read_text(encoding="utf-8", errors="ignore")
                    suspicious = ["curl ", "wget ", "python ", "python3 ", "nc ", "ncat ", "bash -i"]
                    for line in content.splitlines():
                        for marker in suspicious:
                            if marker in line.lower():
                                threats.append(Threat(
                                    id=self._next_id(),
                                    file_path=str(ppath),
                                    threat_type="persistence_mechanism",
                                    severity="high",
                                    confidence=0.6,
                                    evidence=f"Suspicious line: {line.strip()[:120]}",
                                    recommendation="Review startup scripts for unauthorized entries.",
                                ))
                                break
                except Exception:
                    pass
            elif ppath.is_dir():
                for child in ppath.iterdir():
                    if child.is_file():
                        try:
                            content = child.read_text(encoding="utf-8", errors="ignore")
                            if any(m in content.lower() for m in ["exec", "eval", "socket", "subprocess"]):
                                threats.append(Threat(
                                    id=self._next_id(),
                                    file_path=str(child),
                                    threat_type="persistence_mechanism",
                                    severity="medium",
                                    confidence=0.5,
                                    evidence=f"Suspicious content in systemd/cron file",
                                    recommendation="Review scheduled task files.",
                                ))
                        except Exception:
                            pass

        return threats

    # -- internal checkers ------------------------------------------------

    def _check_dangerous_builtins(self, path: Path, content: str) -> list[Threat]:
        threats: list[Threat] = []
        for lineno, line in enumerate(content.splitlines(), 1):
            for match in _DANGEROUS_BUILTINS_RE.finditer(line):
                threats.append(Threat(
                    id=self._next_id(),
                    file_path=str(path),
                    threat_type="dangerous_builtin",
                    severity="high",
                    confidence=0.85,
                    evidence=f"Line {lineno}: {line.strip()[:160]}",
                    recommendation=f"Avoid {match.group(1)}(). Use ast.literal_eval() or safer alternatives.",
                ))
        return threats

    def _check_credentials(self, path: Path, content: str) -> list[Threat]:
        threats: list[Threat] = []
        for cred_type, pattern, recommendation in _CREDENTIAL_PATTERNS:
            for match in pattern.finditer(content):
                threats.append(Threat(
                    id=self._next_id(),
                    file_path=str(path),
                    threat_type=cred_type,
                    severity="critical" if "private" in cred_type or "secret" in cred_type else "high",
                    confidence=0.9,
                    evidence=f"Match: {match.group(0)[:80]}",
                    recommendation=recommendation,
                ))
        return threats

    def _check_obfuscation(self, path: Path, content: str) -> list[Threat]:
        threats: list[Threat] = []
        for obs_type, pattern, recommendation in _OBFUSCATION_PATTERNS:
            for match in pattern.finditer(content):
                threats.append(Threat(
                    id=self._next_id(),
                    file_path=str(path),
                    threat_type=obs_type,
                    severity="high",
                    confidence=0.75,
                    evidence=f"Match: {match.group(0)[:120]}",
                    recommendation=recommendation,
                ))
        return threats

    def _check_malicious_patterns(self, path: Path, content: str) -> list[Threat]:
        threats: list[Threat] = []
        for mal_type, pattern, recommendation in _MALICIOUS_PATTERNS:
            for match in pattern.finditer(content):
                threats.append(Threat(
                    id=self._next_id(),
                    file_path=str(path),
                    threat_type=mal_type,
                    severity="critical" if mal_type in ("reverse_shell", "code_injection") else "high",
                    confidence=0.8,
                    evidence=f"Match: {match.group(0)[:120]}",
                    recommendation=recommendation,
                ))
        return threats

    def _check_file_permissions(self, dir_path: str) -> list[Threat]:
        """Check for world-writable sensitive files."""
        threats: list[Threat] = []
        root = Path(dir_path)
        if not root.is_dir():
            return threats

        for fpath in root.rglob("*"):
            if not fpath.is_file():
                continue
            try:
                mode = fpath.stat().st_mode
                is_world_writable = mode & stat.S_IWOTH
                is_sensitive = any(s in str(fpath) for s in _PERMISSION_SENSITIVE_PATHS)
                if is_world_writable and is_sensitive:
                    threats.append(Threat(
                        id=self._next_id(),
                        file_path=str(fpath),
                        threat_type="world_writable_sensitive_file",
                        severity="high",
                        confidence=0.9,
                        evidence=f"World-writable permissions: {oct(mode)}",
                        recommendation="Remove world-write permission: chmod o-w <file>",
                    ))
            except Exception:
                pass
        return threats

    def _check_credential_file(self, path: Path, content: str) -> list[Threat]:
        """Check if the file itself is a known credential store."""
        threats: list[Threat] = []
        if path.name in _CREDENTIAL_FILE_NAMES:
            # Check if it actually contains credential-like content
            if _SENSITIVE_KEYS_IN_CONFIG.search(content):
                threats.append(Threat(
                    id=self._next_id(),
                    file_path=str(path),
                    threat_type="credential_file_exposed",
                    severity="critical",
                    confidence=0.9,
                    evidence=f"Credential file '{path.name}' contains plaintext secrets",
                    recommendation="Move secrets to a vault or encrypted store. Add to .gitignore.",
                ))
        return threats

    # -- utility ----------------------------------------------------------

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Return True if *ip* is in a private (RFC-1918) range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True
        return False

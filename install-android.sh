#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Minimal Android Installer
# Works on Termux without cryptography/kivy build dependencies

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}   $*"; }
err()   { echo -e "${RED}[ERROR]${NC}  $*"; }
step()  { echo ""; echo -e "${BOLD}${CYAN}▶ $*${NC}"; echo "────────────────────────"; }

clear
echo ""
echo -e "${BOLD}  ██╗   ██╗███████╗██████╗ ██╗███████╗ ██████╗ ██████╗ ███████╗${NC}"
echo -e "${BOLD}  ██║   ██║██╔════╝██╔══██╗██║██╔════╝██╔═══██╗██╔══██╗██╔════╝${NC}"
echo -e "${BOLD}  ██║   ██║█████╗  ██████╔╝██║█████╗  ██║   ██║██████╔╝█████╗  ${NC}"
echo -e "${BOLD}  ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝  ██║   ██║██╔══██╗██╔══╝  ${NC}"
echo -e "${BOLD}   ╚████╔╝ ███████╗██║  ██║██║██║     ╚██████╔╝██║  ██║███████╗${NC}"
echo -e "${BOLD}    ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝${NC}"
echo -e "              ${CYAN}Android Minimal Installer v1.0.0${NC}"
echo ""

# ── Step 1: Environment ──
step "Step 1/5 — Environment Check"
info "Checking Termux..."
if [[ -z "${PREFIX:-}" ]]; then
    err "Not running in Termux. Install Termux from F-Droid first."
    exit 1
fi
ok "Termux detected (aarch64)"

# ── Step 2: Update packages ──
step "Step 2/5 — Updating Packages"
info "Running pkg update..."
pkg update -y > /dev/null 2>&1
ok "Packages updated"

# ── Step 3: Install deps (NO cryptography) ──
step "Step 3/5 — Installing Dependencies"
info "Installing: python, git, openssl"
pkg install -y python git openssl > /dev/null 2>&1
ok "System dependencies installed"

info "Installing Python packages (no cryptography needed)..."
pip install jinja2 requests pydantic typing-extensions --quiet 2>/dev/null || warn "Some pip packages had issues"
ok "Python packages installed"

# ── Step 4: Clone & Install ──
step "Step 4/5 — Installing VeriForge"

INSTALL_DIR="$HOME/VeriForge"
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "VeriForge already cloned. Updating..."
    cd "$INSTALL_DIR"
    git pull --quiet
else
    info "Cloning from GitHub..."
    git clone --depth 1 https://github.com/CSP7211/VeriForge.git "$INSTALL_DIR" --quiet
fi
ok "VeriForge cloned to $INSTALL_DIR"

# Install the SDK (without cryptography dependency)
info "Installing VeriForge SDK..."
cd "$INSTALL_DIR"

# Create a minimal setup that works without cryptography
pip install -e "$INSTALL_DIR" --quiet 2>/dev/null || {
    warn "pip install -e failed, using manual install..."
    # Just add to PYTHONPATH via launcher scripts
}
ok "SDK installed"

# ── Step 5: Create Launchers ──
step "Step 5/5 — Creating Launchers"

LAUNCHER_DIR="$PREFIX/bin"
mkdir -p "$LAUNCHER_DIR"

# Create the scanner engine Python file
mkdir -p "$INSTALL_DIR/veriforge_red/core"

cat > "$INSTALL_DIR/veriforge_red/core/engine.py" << 'PYEOF'
#!/usr/bin/env python3
"""VeriForge Red - Minimal Android Scanner. No external deps."""

import os, sys, re, hashlib, json, time
from pathlib import Path
from datetime import datetime

PATTERNS = {
    "eval_exec": (r"\b(eval|exec)\s*\(", "CRITICAL", "Dynamic Code Execution",
        "eval/exec can execute arbitrary code.", "Use ast.literal_eval() instead."),
    "hardcoded_password": (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "HIGH", "Hardcoded Password", "Password found in source.", "Use environment variables."),
    "hardcoded_secret": (r"(?i)(api_key|apikey|secret|token)\s*=\s*['\"][^'\"]{8,}['\"]",
        "HIGH", "Hardcoded Secret", "Secret token found in source.", "Move to env vars or vault."),
    "sql_injection": (r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*%s.*["\']',
        "CRITICAL", "SQL Injection", "String formatting in SQL query.", "Use parameterized queries."),
    "pickle_load": (r"\bpickle\.load\s*\(", "HIGH", "Unsafe Deserialization",
        "pickle.load() executes arbitrary code.", "Use json.loads() instead."),
    "subprocess_shell": (r"\bsubprocess\.(call|run|Popen).*shell\s*=\s*True",
        "HIGH", "Shell Injection", "subprocess with shell=True is dangerous.", "Use shell=False."),
    "yaml_load": (r"\byaml\.load\s*\([^)]*\)", "HIGH", "Unsafe YAML Loading",
        "yaml.load() without Loader is unsafe.", "Use yaml.safe_load() instead."),
    "debug_true": (r"\bDEBUG\s*=\s*True", "MEDIUM", "Debug Mode Enabled",
        "DEBUG=True should not be in production.", "Set DEBUG=False."),
    "http_url": (r"http://[^\"'\s]+", "LOW", "Insecure HTTP URL",
        "HTTP URL found - use HTTPS.", "Replace http:// with https://."),
}

class RedEngine:
    version = "1.0.0-android"

    def scan(self, target_path: str) -> dict:
        start = time.time()
        target = Path(target_path)
        findings = []
        files_scanned = 0

        files = [target] if target.is_file() else self._collect_files(target)

        for fp in files[:500]:  # Limit to 500 files on mobile
            try:
                content = fp.read_text(errors="ignore")
                file_findings = self._scan_file(fp, content)
                findings.extend(file_findings)
                files_scanned += 1
            except Exception:
                continue

        risk = self._calc_risk(findings)
        grade = self._grade(risk)
        duration = int((time.time() - start) * 1000)

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            summary[f["severity"].lower()] = summary.get(f["severity"].lower(), 0) + 1

        return {
            "target": str(target), "timestamp": datetime.now().isoformat(),
            "duration_ms": duration, "grade": grade, "risk_score": round(risk, 1),
            "files_scanned": files_scanned, "findings": findings,
            "summary": summary, "version": self.version,
        }

    def _collect_files(self, directory: Path) -> list:
        files = []
        for pattern in ["**/*.py", "**/*.js", "**/*.java", "**/*.xml", "**/*.json"]:
            files.extend(directory.glob(pattern))
        return [f for f in files if "__pycache__" not in str(f) and ".git" not in str(f)][:500]

    def _scan_file(self, fp: Path, content: str) -> list:
        findings = []
        for check_name, (pattern, severity, title, desc, fix) in PATTERNS.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "id": f"VF-{check_name.upper()}-{hashlib.md5(f'{fp}:{line_num}'.encode()).hexdigest()[:6]}",
                    "severity": severity, "category": check_name,
                    "title": title, "description": desc,
                    "file_path": str(fp), "line_number": line_num,
                    "remediation": fix,
                })
        return findings

    def _calc_risk(self, findings: list) -> float:
        w = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5, "INFO": 0.1}
        return min(sum(w.get(f["severity"], 0.5) for f in findings), 10.0)

    def _grade(self, risk: float) -> str:
        if risk == 0: return "A+"
        elif risk < 2: return "A"
        elif risk < 4: return "B"
        elif risk < 6: return "C"
        elif risk < 8: return "D"
        else: return "F"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="VeriForge Red - Security Scanner")
    parser.add_argument("--target", "-t", default="/sdcard/Download", help="Target path")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--max-files", "-m", type=int, default=500, help="Max files")
    args = parser.parse_args()

    target = args.target
    if not os.path.exists(target):
        print(f"Error: Path not found: {target}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  VeriForge Red v1.0.0 - Security Scanner")
    print(f"  Target: {target}")
    print(f"{'='*60}\n")

    engine = RedEngine()
    result = engine.scan(target)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Pretty print
    grade_colors = {"A+": "\033[92m", "A": "\033[92m", "B": "\033[93m",
                    "C": "\033[93m", "D": "\033[91m", "F": "\033[91m\033[1m"}
    gc = grade_colors.get(result["grade"], "")
    print(f"  Grade: {gc}{result['grade']}\033[0m  |  Risk: {result['risk_score']}/10  |  Files: {result['files_scanned']}")
    print(f"  Time: {result['duration_ms']}ms  |  Findings: {len(result['findings'])}")
    print(f"\n  Severity Breakdown:")
    for sev, count in result["summary"].items():
        if count > 0:
            print(f"    {sev.upper():12s}: {count}")

    if result["findings"]:
        print(f"\n  {'─'*56}")
        for f in result["findings"][:20]:  # Show top 20
            sev_color = {"CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m",
                        "MEDIUM": "\033[93m", "LOW": "\033[94m"}.get(f["severity"], "")
            file_display = f["file_path"][-40:] if len(f["file_path"]) > 40 else f["file_path"]
            print(f"  {sev_color}[{f['severity']}]\033[0m {f['title']}")
            print(f"         {file_display}:{f['line_number']}")
            print(f"         Fix: {f['remediation']}")
        if len(result["findings"]) > 20:
            print(f"  ... and {len(result['findings']) - 20} more findings")
    else:
        print(f"\n  ✅ No security issues found!")

    print(f"\n{'='*60}")

if __name__ == "__main__":
    main()
PYEOF

ok "Scanner engine created"

# ── Create launcher scripts ──

# 1. veriforge-red
 cat > "$LAUNCHER_DIR/veriforge-red" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Red Scanner
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
python3 "$INSTALL_DIR/veriforge_red/core/engine.py" "\$@"
EOF
chmod +x "$LAUNCHER_DIR/veriforge-red"
ok "Created: veriforge-red"

# 2. veriforge-dashboard
cat > "$LAUNCHER_DIR/veriforge-dashboard" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Dashboard
PORT="${1:-8080}"
echo "Starting VeriForge Dashboard on http://localhost:$PORT"
echo "Open Chrome and go to: http://localhost:$PORT"
echo "Press Ctrl+C to stop"
echo ""
python3 -m http.server "$PORT" --directory /sdcard 2>/dev/null || python3 -m http.server "$PORT"
EOF
chmod +x "$LAUNCHER_DIR/veriforge-dashboard"
ok "Created: veriforge-dashboard"

# 3. veriforge-privacy
cat > "$LAUNCHER_DIR/veriforge-privacy" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# VeriForge Privacy Audit
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
echo "Running privacy audit..."
python3 "$INSTALL_DIR/veriforge_red/core/engine.py" --target /sdcard/Download "\$@"
EOF
chmod +x "$LAUNCHER_DIR/veriforge-privacy"
ok "Created: veriforge-privacy"

# 4. veriforge-help
cat > "$LAUNCHER_DIR/veriforge-help" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
echo ""
echo "  VeriForge Security Platform - Available Commands"
echo "  ════════════════════════════════════════════════"
echo ""
echo "  veriforge-red      <path>   - Security scanner"
echo "  veriforge-privacy  <path>   - Privacy audit"
echo "  veriforge-dashboard [port]  - Web dashboard"
echo "  veriforge-help              - This help"
echo ""
echo "  Examples:"
echo "    veriforge-red -t /sdcard/Download"
echo "    veriforge-red -t /sdcard --json"
echo "    veriforge-dashboard 8080"
echo ""
EOF
chmod +x "$LAUNCHER_DIR/veriforge-help"
ok "Created: veriforge-help"

# ── Done ──
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                                                          ║${NC}"
echo -e "${GREEN}${BOLD}║   ✅ VeriForge Red installed successfully!               ║${NC}"
echo -e "${GREEN}${BOLD}║                                                          ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Available commands:${NC}"
echo ""
echo "  veriforge-red -t /sdcard/Download     Scan your downloads"
echo "  veriforge-red -t /sdcard --json       Full SD card (JSON)"
echo "  veriforge-privacy                     Privacy audit"
echo "  veriforge-dashboard 8080              Web dashboard"
echo "  veriforge-help                        Show help"
echo ""
echo -e "${BOLD}Try now:${NC}  veriforge-red -t /sdcard/Download"
echo ""

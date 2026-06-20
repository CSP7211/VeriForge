# VeriClaw Deployment Guide

**Version:** 0.5.0

---

## Table of Contents

1. [Installation](#installation)
2. [Environment Variables](#environment-variables)
3. [Docker Deployment](#docker-deployment)
4. [CI/CD Integration](#cicd-integration)
   - [GitHub Actions](#github-actions)
   - [GitLab CI](#gitlab-ci)
5. [MCP Server Setup](#mcp-server-setup)
6. [Policy Configuration](#policy-configuration)
7. [Security Hardening](#security-hardening)

---

## Installation

### From PyPI (recommended)

```bash
pip install vericlaw
```

This installs VeriClaw along with its required runtime dependencies:

| Package | Purpose |
|---------|---------|
| `veriforge` | Hardened verification engine |
| `jinja2` | Report template rendering |
| `ast-decompiler` | AST round-tripping for mutations |

### From source

```bash
git clone https://github.com/vericlaw/vericlaw.git
cd vericlaw
pip install -e ".[dev]"
```

### Verify installation

```bash
python -c "import vericlaw; print(vericlaw.__version__)"
# Expected: 0.5.0
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VERIFORGE_SECRET_KEY` | **Yes** (for certification) | *(none)* | Secret key for HMAC-SHA256 certificate signing. Must be at least 32 bytes. Generate with `openssl rand -hex 32`. |
| `VERICLAW_TIMEOUT` | No | `300` | Maximum scan duration per target (seconds). |
| `VERICLAW_MAX_MUTATIONS` | No | `50` | Upper bound on adversarial mutations per entry point. |
| `VERICLAW_SWARM_SIZE` | No | `5` | Number of parallel agents in red-team / fuzzing swarms. |
| `VERICLAW_POLICY_LEVEL` | No | `standard` | Policy strictness: `strict`, `standard`, or `permissive`. |
| `VERICLAW_OUTPUT_DIR` | No | `./vericlaw-reports` | Directory for generated reports. |
| `VERICLAW_SARIF_OUTPUT` | No | `false` | Emit SARIF files in addition to HTML reports. |
| `VERICLAW_MARKDOWN_OUTPUT` | No | `false` | Emit Markdown summaries in addition to HTML reports. |

### Example `.env` file

```bash
# .env
VERIFORGE_SECRET_KEY=a3f7c2d8e9b1045a6d7e8f9012345678abcdef1234567890abcdef12345678
VERICLAW_TIMEOUT=600
VERICLAW_MAX_MUTATIONS=100
VERICLAW_POLICY_LEVEL=strict
VERICLAW_OUTPUT_DIR=./security-reports
VERICLAW_SARIF_OUTPUT=true
VERICLAW_MARKDOWN_OUTPUT=true
```

Load with:

```bash
export $(grep -v '^#' .env | xargs)
```

---

## Docker Deployment

### Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install VeriClaw
RUN pip install --no-cache-dir vericlaw==0.5.0

# Create report output directory
RUN mkdir -p /app/reports

# Copy target code (mount at runtime instead for CI)
# COPY . /app/target/

# Default: run scan on mounted /app/target
ENTRYPOINT ["python", "-m", "vericlaw"]
CMD ["scan", "/app/target"]
```

### Build and run

```bash
# Build image
docker build -t vericlaw:0.5.0 .

# Scan a local project
docker run --rm \
  -e VERIFORGE_SECRET_KEY="$(cat .secret_key)" \
  -e VERICLAW_POLICY_LEVEL=strict \
  -v "$(pwd):/app/target:ro" \
  -v "$(pwd)/reports:/app/reports" \
  vericlaw:0.5.0 \
  scan /app/target --output /app/reports

# Results will be in ./reports/
```

### Docker Compose (service mode)

```yaml
# docker-compose.yml
version: "3.9"

services:
  vericlaw:
    image: vericlaw:0.5.0
    environment:
      VERIFORGE_SECRET_KEY: ${VERIFORGE_SECRET_KEY}
      VERICLAW_TIMEOUT: "600"
      VERICLAW_POLICY_LEVEL: strict
      VERICLAW_SARIF_OUTPUT: "true"
      VERICLAW_MARKDOWN_OUTPUT: "true"
    volumes:
      - ./src:/app/target:ro
      - ./reports:/app/reports
    command: scan /app/target --output /app/reports
```

Run:

```bash
docker compose up vericlaw
```

---

## CI/CD Integration

### GitHub Actions

Add `.github/workflows/security.yml` to your repository:

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'   # Weekly on Monday at 06:00 UTC

jobs:
  vericlaw:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # For SARIF upload to GitHub Security tab
      pull-requests: write      # For PR comment with Markdown summary

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install VeriClaw
        run: pip install vericlaw==0.5.0

      - name: Run VeriClaw scan
        env:
          VERIFORGE_SECRET_KEY: ${{ secrets.VERIFORGE_SECRET_KEY }}
          VERICLAW_POLICY_LEVEL: strict
          VERICLAW_SARIF_OUTPUT: "true"
          VERICLAW_MARKDOWN_OUTPUT: "true"
        run: |
          python -m vericlaw scan . \
            --output reports/ \
            --format all

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        with:
          name: vericlaw-report
          path: reports/*.html

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/report.sarif

      - name: Post Markdown summary to PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const md = fs.readFileSync('reports/report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: md
            });

      - name: Enforce security gate
        run: |
          python -m vericlaw gate reports/result.json --policy strict
```

#### Required secrets

Add in **Settings > Secrets and variables > Actions**:

| Secret | Description |
|--------|-------------|
| `VERIFORGE_SECRET_KEY` | HMAC signing key for certificates |

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security
  - deploy

variables:
  VERICLAW_VERSION: "0.5.0"
  VERICLAW_POLICY_LEVEL: "strict"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip

vericlaw_scan:
  stage: security
  image: python:3.12-slim
  variables:
    VERIFORGE_SECRET_KEY: "$VERIFORGE_SECRET_KEY"
  before_script:
    - pip install vericlaw==${VERICLAW_VERSION}
  script:
    - python -m vericlaw scan . --output reports/ --format all
    - python -m vericlaw gate reports/result.json --policy ${VERICLAW_POLICY_LEVEL}
  artifacts:
    when: always
    paths:
      - reports/
    reports:
      # GitLab ingests SARIF into Vulnerability Report
      reports/sarif: reports/*.sarif
  allow_failure: false   # Set true for warn-only mode
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_COMMIT_BRANCH == "develop"'
```

#### Required CI/CD variables

Add in **Settings > CI/CD > Variables**:

| Variable | Masked | Description |
|----------|--------|-------------|
| `VERIFORGE_SECRET_KEY` | Yes | HMAC signing key |

### Policy Gate Behavior

The `vericlaw gate` command exits with code `0` (pass) or `1` (fail):

| Policy level | Fail conditions |
|--------------|-----------------|
| `strict` | Any critical/high finding OR grade below B |
| `standard` | Any critical finding OR grade below C |
| `permissive` | Grade F only |

---

## MCP Server Setup

VeriClaw exposes tools via the Model Context Protocol (MCP) for integration
with Claude Desktop, Cursor, and other MCP-compatible clients.

### Available tools

| Tool | Description |
|------|-------------|
| `vericlaw_scan` | Run a full adversarial scan on a target path |
| `vericlaw_red_team` | Launch autonomous red-team simulation |
| `vericlaw_certify` | Generate a signed security certificate |
| `vericlaw_explain` | Explain a finding with remediation context |

### Claude Desktop configuration

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "vericlaw": {
      "command": "python",
      "args": ["-m", "vericlaw.mcp_tools"],
      "env": {
        "VERIFORGE_SECRET_KEY": "your-secret-key-here",
        "VERICLAW_POLICY_LEVEL": "strict",
        "VERICLAW_TIMEOUT": "300"
      }
    }
  }
}
```

Restart Claude Desktop after editing. VeriClaw tools will appear in the
**Tools** panel.

### Cursor IDE configuration

Add to Cursor's MCP settings (`.cursor/mcp.json` in your project):

```json
{
  "mcpServers": {
    "vericlaw": {
      "command": "python",
      "args": ["-m", "vericlaw.mcp_tools"],
      "env": {
        "VERIFORGE_SECRET_KEY": "${VERIFORGE_SECRET_KEY}"
      }
    }
  }
}
```

Cursor will load environment variables from your shell or `.env` file.

### Testing the MCP connection

```bash
# Verify the MCP server starts correctly
python -m vericlaw.mcp_tools --health-check

# Expected output:
# MCP server healthy
# Registered tools: vericlaw_scan, vericlaw_red_team, vericlaw_certify, vericlaw_explain
```

---

## Policy Configuration

Policies control whether a build passes or fails based on scan results.

### Policy levels

| Level | Critical | High | Medium | Low | Min Grade |
|-------|----------|------|--------|-----|-----------|
| `strict` | 0 allowed | 0 allowed | any | any | B |
| `standard` | 0 allowed | any | any | any | C |
| `permissive` | any | any | any | any | F (pass) |

### Custom policy file

Create `vericlaw-policy.yaml`:

```yaml
# vericlaw-policy.yaml
version: "1.0"
level: custom
rules:
  max_critical: 0
  max_high: 2
  max_medium: 10
  min_grade: "C"
  required_proofs:
    - type_safety
    - memory_safety
  blocked_cwes:
    - "89"    # SQL Injection
    - "79"    # XSS
    - "94"    # Code Injection
severity_weights:
  critical: 10
  high: 5
  medium: 2
  low: 1
```

Apply:

```bash
python -m vericlaw scan . --policy vericlaw-policy.yaml
```

### Per-directory policy overrides

Place `.vericlaw-policy.yaml` in any subdirectory to override the global
policy for that subtree:

```yaml
# tests/.vericlaw-policy.yaml
# Tests are allowed more leeway
level: permissive
rules:
  max_critical: 0
  max_high: 5
```

---

## Security Hardening

### Secret key management

**Never** commit `VERIFORGE_SECRET_KEY` to version control.

**Recommended approaches:**

```bash
# 1. Generate a strong key
openssl rand -hex 32 > .secret_key
chmod 600 .secret_key

# 2. Use a secrets manager
export VERIFORGE_SECRET_KEY=$(aws secretsmanager get-secret-value \
  --secret-id vericlaw-signing-key \
  --query SecretString --output text)

# 3. Use HashiCorp Vault
export VERIFORGE_SECRET_KEY=$(vault kv get -field=key secret/vericlaw)
```

### Certificate validation in CI

```bash
# Verify certificate signature before deployment
python -m vericlaw verify-cert reports/certificate.json \
  --secret-key "$VERIFORGE_SECRET_KEY"

# Exit code 0 = valid, 1 = invalid/expired
```

### Network isolation

VeriClaw performs **no external network calls** at runtime. For defense in
depth, run scans in a network-isolated container:

```bash
docker run --rm --network none \
  -v "$(pwd):/app/target:ro" \
  vericlaw:0.5.0 scan /app/target
```

### Resource limits

```yaml
# docker-compose.yml with resource limits
services:
  vericlaw:
    image: vericlaw:0.5.0
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 512M
```

---

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| `TemplateNotFound: certificate.html` | Package not installed with templates | `pip install vericlaw` (not `-e .` without package data) |
| SARIF upload fails in GitHub Actions | Missing `security-events: write` permission | Add to workflow `permissions` block |
| Certificate signature invalid | Wrong secret key | Verify `VERIFORGE_SECRET_KEY` matches signing key |
| Gate fails unexpectedly | Policy level too strict | Adjust `VERICLAW_POLICY_LEVEL` or use custom policy |
| Out of memory on large projects | Default limits too high | Reduce `VERICLAW_MAX_MUTATIONS` and `VERICLAW_SWARM_SIZE` |
| Dark theme not applied | Browser/OS theme mismatch | Check `prefers-color-scheme` media query support |

---

## Support

- **Issues:** https://github.com/vericlaw/vericlaw/issues
- **Documentation:** https://docs.vericlaw.dev
- **Security:** security@vericlaw.dev (PGP key available)

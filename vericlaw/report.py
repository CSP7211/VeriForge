"""VeriClaw reporting engine.

Generate interactive HTML reports, SARIF v2.1.0 exports, and Markdown summaries
from scan results.  All output is self-contained (no external CSS/JS dependencies
for the HTML report).
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, PackageLoader, select_autoescape

from .models import (
    AttackSurface,
    Boundary,
    DataFlow,
    EntryPoint,
    Finding,
    Mutation,
    Payload,
    PropertyProof,
    ScanResult,
    SecurityCertificate,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
VERICLAW_VERSION = "0.5.0"

# Severity ordering for stable sorts
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Grade-to-colour mapping used by both HTML and Markdown reports
GRADE_COLOUR = {
    "A+": "#27ae60",
    "A": "#2ecc71",
    "B": "#f39c12",
    "C": "#e67e22",
    "D": "#e74c3c",
    "F": "#c0392b",
}

SEVERITY_ICON = {
    "critical": "&#x26A0;",   # warning sign
    "high": "&#x1F525;",       # fire
    "medium": "&#x1F536;",     # large orange diamond
    "low": "&#x1F538;",        # small orange diamond
    "info": "&#x2139;",        # information source
}

SEVERITY_COLOUR = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}


def _grade_colour(grade: str) -> str:
    """Return hex colour for a grade string."""
    return GRADE_COLOUR.get(grade.upper(), "#7f8c8d")


def _severity_sort_key(severity: str) -> int:
    return SEVERITY_RANK.get(severity.lower(), 99)


def _h(v: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(v))


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generate human- and machine-readable reports from VeriClaw scan results.

    Three primary output formats are supported:

    * **HTML** (`generate_html`) — self-contained interactive report with
      inline CSS, sortable tables, risk gauge, and dark-mode support.
    * **SARIF** (`generate_sarif`) — SARIF v2.1.0 JSON for CI/CD ingestion.
    * **Markdown** (`generate_markdown`) — concise summary for PR comments.

    Example::

        gen = ReportGenerator()
        html_report = gen.generate_html(scan_result)
        sarif_doc   = gen.generate_sarif(scan_result)
        md_summary  = gen.generate_markdown(scan_result)
    """

    # ------------------------------------------------------------------ #
    #  HTML report
    # ------------------------------------------------------------------ #

    def generate_html(self, result: ScanResult) -> str:
        """Return a self-contained HTML report string for *result*.

        The report includes:

        * Executive summary with a colour-coded grade badge.
        * Visual risk-score gauge (0–10).
        * Sortable findings table with severity icons.
        * Attack-surface visualisation (entry points + data flows).
        * Property-proofs table with pass/fail indicators.
        * Mutations table showing original → mutated code.
        * Payloads section with syntax-highlighted snippets.
        * Certificate / signature-verification block (if available).
        * Attack-chain flow diagram.
        * Remediation recommendations per finding.

        All CSS is inline; no external network dependencies.  Dark theme is
        provided via ``prefers-color-scheme: dark``.
        """
        if not isinstance(result, ScanResult):
            raise TypeError("result must be a ScanResult instance")

        sorted_findings = sorted(
            result.findings,
            key=lambda f: (_severity_sort_key(f.severity), f.title),
        )
        grade_col = _grade_colour(result.grade)
        risk_pct = max(0.0, min(100.0, result.risk_score * 10.0))
        cert = result.certificate

        sections: list[str] = []
        sections.append(self._html_head(result))
        sections.append(self._html_summary(result, grade_col, risk_pct))
        sections.append(self._html_findings(sorted_findings))
        sections.append(self._html_attack_surface(result.attack_surface))
        sections.append(self._html_proofs(result.proofs))
        sections.append(self._html_mutations(result.mutations))
        sections.append(self._html_payloads(result.payloads))
        if cert:
            sections.append(self._html_certificate(cert))
        sections.append(self._html_attack_chain(result))
        sections.append(self._html_remediation(sorted_findings))
        sections.append(self._html_footer(result))

        return "\n".join(sections)

    # -- individual HTML sections --------------------------------------- #

    @staticmethod
    def _html_head(result: ScanResult) -> str:
        title = _h(result.target)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VeriClaw Report — {_h(title)}</title>
<style>
:root {{
  --bg: #f4f6f8;
  --fg: #1a1a2e;
  --card: #ffffff;
  --card-border: #d1d5db;
  --accent: #3b82f6;
  --muted: #6b7280;
  --pass: #22c55e;
  --fail: #ef4444;
  --warn: #f59e0b;
  --code-bg: #f3f4f6;
  --radius: 12px;
  --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
  --mono: 'Fira Code', 'Cascadia Code', Consolas, monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0f172a;
    --fg: #e2e8f0;
    --card: #1e293b;
    --card-border: #334155;
    --accent: #60a5fa;
    --muted: #94a3b8;
    --pass: #4ade80;
    --fail: #f87171;
    --warn: #fbbf24;
    --code-bg: #0b1120;
  }}
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; }}
body {{ font-family: var(--font); background: var(--bg); color: var(--fg);
        line-height: 1.6; padding: 1rem; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
.card {{ background: var(--card); border: 1px solid var(--card-border);
         border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.5rem;
         box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
h1, h2, h3 {{ font-weight: 700; letter-spacing: -0.02em; margin-bottom: 0.75rem; }}
h1 {{ font-size: 1.75rem; }} h2 {{ font-size: 1.35rem; }} h3 {{ font-size: 1.1rem; }}
.badge {{ display: inline-flex; align-items: center; justify-content: center;
          width: 64px; height: 64px; border-radius: 50%; font-size: 1.4rem;
          font-weight: 800; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.2);
          box-shadow: 0 0 0 4px rgba(255,255,255,0.15), 0 4px 12px rgba(0,0,0,0.15); }}
.gauge-container {{ position: relative; width: 200px; height: 100px; margin: 1rem auto; }}
.gauge-bg, .gauge-fill {{ width: 200px; height: 100px; border-radius: 100px 100px 0 0;
                           position: absolute; top: 0; left: 0; }}
.gauge-bg {{ background: #e5e7eb; }}
.gauge-fill {{ background: conic-gradient(from 180deg at 50% 100%, var(--accent) 0deg, var(--accent) calc(var(--pct) * 1.8deg), transparent calc(var(--pct) * 1.8deg)); mask: radial-gradient(at 50% 100%, transparent 55%, black 56%); -webkit-mask: radial-gradient(at 50% 100%, transparent 55%, black 56%); border-radius: 100px 100px 0 0; }}
.gauge-needle {{ position: absolute; bottom: 0; left: 50%; width: 3px; height: 90px; background: var(--fg); transform-origin: bottom center; transform: rotate(calc(var(--pct) * 1.8deg - 90deg)); border-radius: 3px; transition: transform 1s ease-out; }}
.gauge-label {{ position: absolute; bottom: -1.5rem; width: 100%; text-align: center; font-weight: 700; font-size: 1.1rem; color: var(--accent); }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
th, td {{ padding: 0.65rem 0.75rem; text-align: left; border-bottom: 1px solid var(--card-border); }}
th {{ background: rgba(59,130,246,0.08); font-weight: 600; cursor: pointer; user-select: none; }}
tr:hover {{ background: rgba(59,130,246,0.04); }}
.sev {{ display: inline-flex; align-items: center; gap: 0.35rem; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; padding: 0.2rem 0.5rem; border-radius: 6px; background: rgba(0,0,0,0.04); }}
.status-pass {{ color: var(--pass); font-weight: 700; }}
.status-fail {{ color: var(--fail); font-weight: 700; }}
.status-warn {{ color: var(--warn); font-weight: 700; }}
pre {{ background: var(--code-bg); padding: 0.85rem; border-radius: 8px; overflow-x: auto; font-family: var(--mono); font-size: 0.82rem; border: 1px solid var(--card-border); }}
code {{ font-family: var(--mono); background: var(--code-bg); padding: 0.15rem 0.35rem; border-radius: 4px; font-size: 0.82em; }}
.chain {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; padding: 0.75rem 0; }}
.chain-step {{ background: var(--accent); color: #fff; padding: 0.4rem 0.8rem; border-radius: 20px; font-size: 0.82rem; font-weight: 600; }}
.chain-arrow {{ color: var(--muted); font-size: 1.2rem; }}
.remediation {{ margin-bottom: 1rem; padding: 1rem; border-left: 4px solid var(--accent); background: rgba(59,130,246,0.04); border-radius: 0 8px 8px 0; }}
.remediation h4 {{ margin-bottom: 0.3rem; }}
.mutation-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }}
.mutation-box {{ background: var(--code-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 0.75rem; font-family: var(--mono); font-size: 0.8rem; }}
.mutation-arrow {{ display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: var(--muted); }}
.payload {{ margin-bottom: 0.75rem; }}
.payload-type {{ font-weight: 600; font-size: 0.8rem; text-transform: uppercase; color: var(--muted); }}
.signature-block {{ display: flex; align-items: center; gap: 0.5rem; font-family: var(--mono); font-size: 0.8rem; }}
.sig-verified {{ color: var(--pass); }}
.sig-invalid {{ color: var(--fail); }}
@media (max-width: 640px) {{
  .mutation-row {{ grid-template-columns: 1fr; }}
  .gauge-container {{ transform: scale(0.85); }}
}}
</style>
</head>
<body>
<div class="container">
<h1>&#x1F512; VeriClaw Security Report</h1>
"""

    @staticmethod
    def _html_summary(result: ScanResult, grade_col: str, risk_pct: float) -> str:
        cert = result.certificate
        sig_status = ""
        if cert:
            verified = "VERIFIED" if cert.signature else "UNSIGNED"
            sig_status = f"<p><strong>Certificate Signature:</strong> {verified}</p>"

        return f"""
<div class="card">
  <h2>Executive Summary</h2>
  <div style="display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem;">
    <div class="badge" style="background:{grade_col};">{_h(result.grade)}</div>
    <div>
      <p style="font-size:1.1rem;font-weight:600;margin-bottom:0.25rem;">{_h(result.target)}</p>
      <p style="color:var(--muted);font-size:0.9rem;">Scanned at {_h(result.timestamp)}</p>
      <p><strong>Findings:</strong> {len(result.findings)} &nbsp;|&nbsp;
         <strong>Proofs:</strong> {len(result.proofs)} &nbsp;|&nbsp;
         <strong>Mutations:</strong> {len(result.mutations)}</p>
      {sig_status}
    </div>
  </div>
  <div class="gauge-container" style="--pct:{risk_pct:.1f};">
    <div class="gauge-bg"></div>
    <div class="gauge-fill"></div>
    <div class="gauge-needle"></div>
    <div class="gauge-label">{_h(result.risk_score)} / 10</div>
  </div>
</div>
"""

    @staticmethod
    def _html_findings(findings: list[Finding]) -> str:
        if not findings:
            return '<div class="card"><h2>Findings</h2><p style="color:var(--muted);">No findings detected.</p></div>'

        rows = []
        for f in findings:
            icon = SEVERITY_ICON.get(f.severity.lower(), "")
            colour = SEVERITY_COLOUR.get(f.severity.lower(), "#7f8c8d")
            cwe = f"<br><small>CWE-{_h(f.cwe_id)}</small>" if f.cwe_id else ""
            cvss = f"<br><small>CVSS: {_h(f.cvss_score)}</small>" if f.cvss_score is not None else ""
            rows.append(
                f"""<tr>
  <td><span class="sev" style="color:{colour};">{icon} {_h(f.severity.upper())}</span></td>
  <td><strong>{_h(f.id)}</strong></td>
  <td>{_h(f.title)}</td>
  <td>{_h(f.category)}</td>
  <td>{_h(f.description[:120])}{'...' if len(f.description) > 120 else ''}</td>
  <td>{_h(f.evidence[:100])}{'...' if len(f.evidence) > 100 else ''}{cwe}{cvss}</td>
</tr>"""
            )

        return f"""
<div class="card">
  <h2>&#x1F50E; Findings ({len(findings)})</h2>
  <div style="overflow-x:auto;">
    <table id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Severity &#x25B2;&#x25BC;</th>
          <th onclick="sortTable(1)">ID &#x25B2;&#x25BC;</th>
          <th onclick="sortTable(2)">Title &#x25B2;&#x25BC;</th>
          <th onclick="sortTable(3)">Category &#x25B2;&#x25BC;</th>
          <th>Description</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
  <script>
  (function() {{
    function sortTable(n) {{
      var table = document.getElementById("findingsTable");
      var rows = Array.from(table.rows).slice(1);
      var asc = table.getAttribute("data-sort-dir") !== "asc";
      rows.sort(function(a, b) {{
        var x = a.cells[n].innerText.toLowerCase();
        var y = b.cells[n].innerText.toLowerCase();
        return asc ? (x > y ? 1 : -1) : (x < y ? 1 : -1);
      }});
      rows.forEach(function(r) {{ table.tBodies[0].appendChild(r); }});
      table.setAttribute("data-sort-dir", asc ? "asc" : "desc");
    }}
    window.sortTable = sortTable;
  }})();
  </script>
</div>
"""

    @staticmethod
    def _html_attack_surface(surface: AttackSurface) -> str:
        entry_rows = ""
        for ep in surface.entry_points:
            risks = ", ".join(ep.risk_indicators) if ep.risk_indicators else "—"
            entry_rows += (
                f"<tr><td>{_h(ep.name)}</td><td>{_h(ep.type)}</td>"
                f"<td>{ep.line}</td><td>{_h(risks)}</td></tr>"
            )

        flow_items = ""
        for df in surface.data_flows:
            path = " → ".join(df.path) if df.path else "direct"
            flow_items += (
                f'<li><strong>{_h(df.source)}</strong> → {_h(path)} → '
                f'<strong>{_h(df.sink)}</strong> '
                f'(<span style="color:{SEVERITY_COLOUR.get(df.taint_level,"var(--muted)")}">'
                f'{_h(df.taint_level)}</span>)</li>'
            )

        boundary_items = ""
        for b in surface.trust_boundaries:
            gaps = ", ".join(b.gaps) if b.gaps else "none identified"
            boundary_items += (
                f"<li><strong>{_h(b.name)}</strong> ({_h(b.type)}) — "
                f"gaps: {_h(gaps)}</li>"
            )

        return f"""
<div class="card">
  <h2>&#x1F4A5; Attack Surface</h2>
  <p><strong>Risk Score:</strong> {surface.risk_score:.1f} / 10</p>

  <h3>Entry Points ({len(surface.entry_points)})</h3>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>Line</th><th>Risk Indicators</th></tr></thead>
      <tbody>{entry_rows or '<tr><td colspan="4" style="color:var(--muted);">No entry points found.</td></tr>'}</tbody>
    </table>
  </div>

  <h3>Data Flows ({len(surface.data_flows)})</h3>
  <ul>{flow_items or '<li style="color:var(--muted);">No taint flows detected.</li>'}</ul>

  <h3>Trust Boundaries ({len(surface.trust_boundaries)})</h3>
  <ul>{boundary_items or '<li style="color:var(--muted);">No trust boundaries identified.</li>'}</ul>
</div>
"""

    @staticmethod
    def _html_proofs(proofs: list[PropertyProof]) -> str:
        if not proofs:
            return '<div class="card"><h2>Property Proofs</h2><p style="color:var(--muted);">No proofs executed.</p></div>'

        rows = ""
        for p in proofs:
            if p.status == "proven":
                cls, icon = "status-pass", "&#x2714;"
            elif p.status == "violated":
                cls, icon = "status-fail", "&#x2718;"
            elif p.status == "timeout":
                cls, icon = "status-warn", "&#x23F1;"
            else:
                cls, icon = "status-warn", "&#x26A0;"
            ce = f"<pre>{_h(p.counterexample)}</pre>" if p.counterexample else "—"
            rows += (
                f"<tr><td class='{cls}'>{icon} {_h(p.property_name)}</td>"
                f"<td class='{cls}'>{_h(p.status.upper())}</td>"
                f"<td>{p.verification_time_ms} ms</td>"
                f"<td>{p.confidence:.0%}</td><td>{ce}</td></tr>"
            )

        return f"""
<div class="card">
  <h2>&#x2705; Property Proofs ({len(proofs)})</h2>
  <div style="overflow-x:auto;">
    <table>
      <thead><tr><th>Property</th><th>Status</th><th>Time</th><th>Confidence</th><th>Counterexample</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
"""

    @staticmethod
    def _html_mutations(mutations: list[Mutation]) -> str:
        if not mutations:
            return '<div class="card"><h2>Mutations</h2><p style="color:var(--muted);">No mutations generated.</p></div>'

        boxes = ""
        for m in mutations:
            sev_col = SEVERITY_COLOUR.get(m.severity.lower(), "#7f8c8d")
            boxes += f"""
<div style="margin-bottom:1.5rem;">
  <p style="font-size:0.85rem;color:var(--muted);margin-bottom:0.4rem;">
    <span class="sev" style="color:{sev_col};">{_h(m.severity.upper())}</span>
    &nbsp;{_h(m.mutation_type)} — {_h(m.description)}
  </p>
  <div class="mutation-row">
    <div>
      <div style="font-size:0.75rem;color:var(--muted);margin-bottom:0.3rem;">ORIGINAL</div>
      <div class="mutation-box"><pre>{_h(m.original)}</pre></div>
    </div>
    <div>
      <div style="font-size:0.75rem;color:var(--muted);margin-bottom:0.3rem;">MUTATED</div>
      <div class="mutation-box" style="border-color:var(--fail);"><pre>{_h(m.mutated)}</pre></div>
    </div>
  </div>
</div>"""

        return f"""
<div class="card">
  <h2>&#x1F9EA; Mutations ({len(mutations)})</h2>
  {boxes}
</div>
"""

    @staticmethod
    def _html_payloads(payloads: list[Payload]) -> str:
        if not payloads:
            return '<div class="card"><h2>Payloads</h2><p style="color:var(--muted);">No payloads generated.</p></div>'

        items = ""
        for p in payloads:
            sev_col = SEVERITY_COLOUR.get(p.severity.lower(), "#7f8c8d")
            items += f"""
<div class="payload">
  <div class="payload-type">{_h(p.payload_type)} &middot; {_h(p.encoding)} &middot;
    <span style="color:{sev_col};">{_h(p.severity.upper())}</span>
  </div>
  <p style="font-size:0.82rem;color:var(--muted);margin-bottom:0.3rem;">Context: {_h(p.context)}</p>
  <pre>{_h(p.content)}</pre>
</div>"""

        return f"""
<div class="card">
  <h2>&#x1F4A3; Payloads ({len(payloads)})</h2>
  {items}
</div>
"""

    @staticmethod
    def _html_certificate(cert: SecurityCertificate) -> str:
        verified = bool(cert.signature and len(cert.signature) > 0)
        cls = "sig-verified" if verified else "sig-invalid"
        status_text = "VERIFIED" if verified else "INVALID / MISSING"
        icon = "&#x2714;" if verified else "&#x2718;"
        return f"""
<div class="card">
  <h2>&#x1F4C3; Security Certificate</h2>
  <p><strong>Target:</strong> {_h(cert.target)}</p>
  <p><strong>Issued:</strong> {_h(cert.timestamp)} &nbsp;|&nbsp; <strong>Expires:</strong> {_h(cert.expires)}</p>
  <p><strong>Grade:</strong> <span style="color:{_grade_colour(cert.grade)};font-weight:700;font-size:1.2rem;">{_h(cert.grade)}</span></p>
  <p><strong>Risk Score:</strong> {cert.risk_score:.1f} / 10</p>
  <div class="signature-block">
    <span class="{cls}">{icon} Signature {status_text}</span>
  </div>
  <p style="font-family:var(--mono);font-size:0.7rem;color:var(--muted);word-break:break-all;margin-top:0.5rem;">
    {_h(cert.signature[:64])}...
  </p>
</div>
"""

    @staticmethod
    def _html_attack_chain(result: ScanResult) -> str:
        # Build chain from attack_surface.attack_vectors if available,
        # otherwise fall back to a generic message.
        vectors = result.attack_surface.attack_vectors
        if not vectors:
            return ''

        steps = []
        for i, v in enumerate(vectors):
            steps.append(f'<span class="chain-step">{i+1}. {_h(v.type)}</span>')
            if i < len(vectors) - 1:
                steps.append('<span class="chain-arrow">&#x27A1;</span>')

        return f"""
<div class="card">
  <h2>&#x1F517; Attack Chain</h2>
  <div class="chain">
    {''.join(steps)}
  </div>
  <p style="color:var(--muted);font-size:0.85rem;margin-top:0.75rem;">
    Ordered attack vectors from entry point to potential compromise.
  </p>
</div>
"""

    @staticmethod
    def _html_remediation(findings: list[Finding]) -> str:
        if not findings:
            return ''

        blocks = ""
        for f in findings:
            sev_col = SEVERITY_COLOUR.get(f.severity.lower(), "#7f8c8d")
            blocks += f"""
<div class="remediation" style="border-left-color:{sev_col};">
  <h4>{_h(f.id)} — {_h(f.title)} <span style="color:{sev_col};">[{_h(f.severity.upper())}]</span></h4>
  <p>{_h(f.remediation)}</p>
</div>"""

        return f"""
<div class="card">
  <h2>&#x1F527; Remediation Recommendations</h2>
  {blocks}
</div>
"""

    @staticmethod
    def _html_footer(result: ScanResult) -> str:
        return f"""
<div style="text-align:center;color:var(--muted);font-size:0.82rem;padding:1rem 0 2rem;">
  <p>Generated by <strong>VeriClaw</strong> v{VERICLAW_VERSION} &middot; {_h(datetime.now(timezone.utc).isoformat())}</p>
</div>
</div>
</body>
</html>
"""

    # ------------------------------------------------------------------ #
    #  SARIF export
    # ------------------------------------------------------------------ #

    def generate_sarif(self, result: ScanResult) -> dict[str, Any]:
        """Return a SARIF v2.1.0 dictionary for *result*.

        The dictionary conforms to the OASIS SARIF specification and can be
        serialised directly with ``json.dump``.
        """
        if not isinstance(result, ScanResult):
            raise TypeError("result must be a ScanResult instance")

        rules: list[dict[str, Any]] = []
        sarif_results: list[dict[str, Any]] = []
        rule_ids: set[str] = set()

        for finding in result.findings:
            rule_id = f"VC-{finding.category.upper().replace(' ', '_')}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": finding.category,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": self._sarif_level(finding.severity),
                    },
                    "properties": {
                        "tags": ["security", finding.category.lower()],
                        "precision": "high",
                    },
                })

            sarif_result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": self._sarif_level(finding.severity),
                "message": {"text": f"[{finding.id}] {finding.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": result.target},
                    },
                }],
                "properties": {
                    "id": finding.id,
                    "title": finding.title,
                    "category": finding.category,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                },
            }
            if finding.cwe_id:
                sarif_result["properties"]["cwe"] = finding.cwe_id
            if finding.cvss_score is not None:
                sarif_result["properties"]["cvssScore"] = finding.cvss_score

            sarif_results.append(sarif_result)

        # Add proofs as informational results
        for proof in result.proofs:
            if proof.status == "violated":
                sarif_results.append({
                    "ruleId": "VC-PROPERTY_VIOLATION",
                    "level": "error",
                    "message": {
                        "text": (
                            f"Property '{proof.property_name}' was violated. "
                            f"Confidence: {proof.confidence:.0%}"
                        ),
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.target},
                        },
                    }],
                    "properties": {
                        "propertyName": proof.property_name,
                        "confidence": proof.confidence,
                        "counterexample": proof.counterexample,
                    },
                })

        invocation: dict[str, Any] = {
            "commandLine": f"vericlaw scan {result.target}",
            "executionSuccessful": True,
            "startTimeUtc": result.timestamp,
        }
        if result.certificate:
            invocation["properties"] = {
                "grade": result.grade,
                "riskScore": result.risk_score,
            }

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "VeriClaw",
                    "version": VERICLAW_VERSION,
                    "informationUri": "https://github.com/vericlaw/vericlaw",
                    "rules": rules,
                },
            },
            "invocations": [invocation],
            "results": sarif_results,
            "automationDetails": {
                "description": {
                    "text": f"VeriClaw scan of {result.target}",
                },
            },
        }

        if result.certificate:
            run["properties"] = {
                "veriClaw": {
                    "grade": result.grade,
                    "riskScore": result.risk_score,
                    "signaturePresent": bool(result.certificate.signature),
                },
            }

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [run],
        }

    @staticmethod
    def _sarif_level(severity: str) -> str:
        """Map VeriClaw severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping.get(severity.lower(), "warning")

    # ------------------------------------------------------------------ #
    #  Markdown report
    # ------------------------------------------------------------------ #

    def generate_markdown(self, result: ScanResult) -> str:
        """Return a concise Markdown summary suitable for GitHub PR comments.

        Includes a grade badge, risk score, finding count by severity, and
        a short table of the top findings.
        """
        if not isinstance(result, ScanResult):
            raise TypeError("result must be a ScanResult instance")

        grade_col = _grade_colour(result.grade)
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines: list[str] = []
        lines.append("## VeriClaw Security Scan Results")
        lines.append("")
        lines.append(f"**Target:** `{result.target}`  ")
        lines.append(f"**Grade:** <span style='color:{grade_col};font-weight:bold'>{result.grade}</span>  ")
        lines.append(f"**Risk Score:** {result.risk_score:.1f} / 10  ")
        lines.append(f"**Findings:** {len(result.findings)}  ")
        lines.append(f"**Timestamp:** {result.timestamp}")
        lines.append("")

        # Severity breakdown
        if severity_counts:
            lines.append("### Severity Breakdown")
            lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                cnt = severity_counts.get(sev, 0)
                if cnt:
                    icon = SEVERITY_ICON.get(sev, "")
                    lines.append(f"- {icon} **{sev.upper()}:** {cnt}")
            lines.append("")

        # Top findings table
        sorted_findings = sorted(
            result.findings,
            key=lambda f: (_severity_sort_key(f.severity), f.title),
        )
        if sorted_findings:
            lines.append("### Top Findings")
            lines.append("")
            lines.append("| Severity | ID | Title | Category |")
            lines.append("|----------|----|-------|----------|")
            for f in sorted_findings[:10]:
                sev_icon = SEVERITY_ICON.get(f.severity.lower(), "")
                lines.append(
                    f"| {sev_icon} {f.severity.upper()} | {f.id} | {f.title} | {f.category} |"
                )
            if len(sorted_findings) > 10:
                lines.append(f"| | | ... and {len(sorted_findings) - 10} more | |")
            lines.append("")

        # Property proofs summary
        if result.proofs:
            proven = sum(1 for p in result.proofs if p.status == "proven")
            violated = sum(1 for p in result.proofs if p.status == "violated")
            lines.append("### Property Proofs")
            lines.append(f"- **Proven:** {proven}")
            lines.append(f"- **Violated:** {violated}")
            lines.append(f"- **Total:** {len(result.proofs)}")
            lines.append("")

        # Mutations & payloads count
        if result.mutations:
            lines.append(f"- **Mutations tested:** {len(result.mutations)}")
        if result.payloads:
            lines.append(f"- **Payloads generated:** {len(result.payloads)}")

        # Certificate
        if result.certificate:
            sig_ok = "VERIFIED" if result.certificate.signature else "MISSING"
            lines.append("")
            lines.append(f"**Certificate Signature:** {sig_ok}")

        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by VeriClaw v{VERICLAW_VERSION}*")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  Certificate rendering via Jinja2
    # ------------------------------------------------------------------ #

    def render_certificate(
        self,
        certificate: SecurityCertificate,
        template_path: Optional[str] = None,
    ) -> str:
        """Render a ``SecurityCertificate`` through the Jinja2 template.

        Parameters
        ----------
        certificate:
            The certificate to render.
        template_path:
            Optional filesystem path to a custom ``certificate.html`` template.
            When *None* the bundled template is used.

        Returns
        -------
        str
            Rendered HTML string.
        """
        if template_path:
            env = Environment(
                loader=FileSystemLoader(str(Path(template_path).parent)),
                autoescape=select_autoescape(["html", "xml"]),
            )
            tmpl = env.get_template(Path(template_path).name)
        else:
            env = Environment(
                loader=PackageLoader("vericlaw", "templates"),
                autoescape=select_autoescape(["html", "xml"]),
            )
            tmpl = env.get_template("certificate.html")

        # Convert dataclass instances to plain dicts for Jinja2
        findings_dicts = [asdict(f) for f in certificate.findings]
        proofs_dicts = [asdict(p) for p in certificate.proofs]

        grade_col = _grade_colour(certificate.grade)
        risk_pct = max(0.0, min(100.0, certificate.risk_score * 10.0))
        verified = bool(certificate.signature and len(certificate.signature) > 0)

        return tmpl.render(
            target=certificate.target,
            grade=certificate.grade,
            grade_colour=grade_col,
            risk_score=certificate.risk_score,
            risk_percentage=risk_pct,
            findings=findings_dicts,
            proofs=proofs_dicts,
            signature=certificate.signature,
            signature_verified=verified,
            timestamp=certificate.timestamp,
            expires=certificate.expires,
            version=VERICLAW_VERSION,
        )

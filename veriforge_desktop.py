#!/usr/bin/env python3
"""
VeriForge Red — Desktop Dashboard
Run: python3 veriforge_desktop.py
Opens: http://localhost:8080
"""
import os, sys, json, time, webbrowser, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Ensure VeriForge is available ──
VF_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, VF_DIR)

for key in ["VERIFORGE_SECRET", "VERIFORGE_JWT_SECRET", "VERIFORGE_AUDIT_SECRET"]:
    if not os.environ.get(key):
        os.environ[key] = os.urandom(32).hex()

from veriforge.engine import VeriForgeEngine
from veriforge.config import SecureConfig
from veriforge.auth import AuthManager
from veriforge.audit import ImmutableAuditLog
from veriforge.compliance import ComplianceAuditor
from veriforge.agent import AgentVerifier
from veriforge.semantic import SemanticAnalyzer

config = SecureConfig()
engine = VeriForgeEngine(config)
auth_mgr = AuthManager(config)
audit_log = ImmutableAuditLog(config)
compliance = ComplianceAuditor()
agent_verifier = AgentVerifier(config)

# ── HTML Dashboard ──
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VeriForge Red — Desktop Dashboard</title>
<style>
:root{--bg:#0a0e17;--panel:#111827;--border:#1f2937;--accent:#ef4444;--accent2:#f59e0b;--text:#e5e7eb;--muted:#9ca3af;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;--info:#3b82f6;}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',system-ui,sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#1f2937 0%,#111827 100%);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:1.4rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}
.header h1::before{content:"🛡️";font-size:1.6rem}
.status-badge{padding:0.35rem 0.9rem;border-radius:9999px;font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em}
.status-badge.online{background:rgba(16,185,129,0.15);color:var(--success);border:1px solid rgba(16,185,129,0.3)}
.status-badge.alert{background:rgba(239,68,68,0.15);color:var(--danger);border:1px solid rgba(239,68,68,0.3)}
.container{max-width:1400px;margin:0 auto;padding:2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:1.5rem;margin-top:1.5rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1.5rem;transition:box-shadow 0.2s}
.card:hover{box-shadow:0 0 30px rgba(239,68,68,0.08)}
.card-title{font-size:1.1rem;font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:0.5rem;color:var(--text)}
.card-title .icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:0.9rem}
.icon-scan{background:rgba(59,130,246,0.15);color:var(--info)}
.icon-audit{background:rgba(245,158,11,0.15);color:var(--warning)}
.icon-auth{background:rgba(16,185,129,0.15);color:var(--success)}
.icon-compliance{background:rgba(139,92,246,0.15);color:#8b5cf6}
.icon-agent{background:rgba(236,72,153,0.15);color:#ec4899}
.icon-semantic{background:rgba(6,182,212,0.15);color:#06b6d4}
.textarea{width:100%;min-height:140px;background:#0d1117;border:1px solid var(--border);border-radius:8px;color:var(--text);padding:0.75rem;font-family:'Consolas','Monaco',monospace;font-size:0.85rem;resize:vertical;outline:none;transition:border-color 0.2s}
.textarea:focus{border-color:var(--accent)}
.btn{padding:0.6rem 1.2rem;border-radius:8px;border:none;font-weight:600;font-size:0.85rem;cursor:pointer;transition:all 0.15s;text-transform:uppercase;letter-spacing:0.03em;display:inline-flex;align-items:center;gap:0.4rem}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#dc2626;transform:translateY(-1px);box-shadow:0 4px 12px rgba(239,68,68,0.3)}
.btn-secondary{background:var(--border);color:var(--text)}
.btn-secondary:hover{background:#374151}
.btn-success{background:var(--success);color:#fff}
.btn-sm{padding:0.4rem 0.8rem;font-size:0.8rem}
.result-panel{margin-top:1rem;padding:1rem;border-radius:8px;background:#0d1117;border:1px solid var(--border);min-height:80px;font-family:monospace;font-size:0.8rem;white-space:pre-wrap;overflow-x:auto;max-height:300px;overflow-y:auto}
.result-panel.pass{border-color:rgba(16,185,129,0.4);background:rgba(16,185,129,0.05)}
.result-panel.fail{border-color:rgba(239,68,68,0.4);background:rgba(239,68,68,0.05)}
.result-panel.warn{border-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.05)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem;text-align:center}
.stat-value{font-size:1.8rem;font-weight:700;color:var(--accent)}
.stat-label{font-size:0.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-top:0.25rem}
.tabs{display:flex;gap:0.25rem;margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem}
.tab{padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-size:0.85rem;font-weight:500;transition:all 0.15s;border:none;background:transparent;color:var(--muted)}
.tab.active{background:rgba(239,68,68,0.1);color:var(--accent)}
.tab:hover{color:var(--text)}
.tab-content{display:none}
.tab-content.active{display:block}
.input-row{display:flex;gap:0.5rem;margin-bottom:0.75rem}
.input-row input{flex:1;padding:0.5rem 0.75rem;background:#0d1117;border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.85rem;outline:none}
.input-row input:focus{border-color:var(--accent)}
.finding-item{padding:0.5rem 0.75rem;border-radius:6px;margin-bottom:0.4rem;font-size:0.8rem;display:flex;align-items:center;gap:0.5rem}
.finding-item.critical{background:rgba(239,68,68,0.1);border-left:3px solid var(--danger)}
.finding-item.warning{background:rgba(245,158,11,0.1);border-left:3px solid var(--warning)}
.finding-item.info{background:rgba(59,130,246,0.1);border-left:3px solid var(--info)}
.empty-state{text-align:center;padding:2rem;color:var(--muted);font-size:0.9rem}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.footer{text-align:center;padding:1.5rem;color:var(--muted);font-size:0.75rem;border-top:1px solid var(--border);margin-top:2rem}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#374151}
</style>
</head>
<body>
<div class="header">
  <h1>VeriForge Red</h1>
  <span class="status-badge online" id="statusBadge">● Online</span>
</div>

<div class="container">
  <div class="stats">
    <div class="stat-card">
      <div class="stat-value" id="statScans">0</div>
      <div class="stat-label">Scans Run</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="statThreats">0</div>
      <div class="stat-label">Threats Blocked</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="statAudits">0</div>
      <div class="stat-label">Audit Entries</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="statVerified">0</div>
      <div class="stat-label">Verified Clean</div>
    </div>
  </div>

  <div class="grid">
    <!-- SCANNER -->
    <div class="card">
      <div class="card-title"><span class="icon icon-scan">🔍</span> Code Scanner</div>
      <div class="tabs">
        <button class="tab active" onclick="switchTab('scan',this)">Paste Code</button>
        <button class="tab" onclick="switchTab('file',this)">Upload File</button>
      </div>
      <div class="tab-content active" id="tab-scan">
        <textarea class="textarea" id="scanCode" placeholder="Paste Python code here to scan...">x = 1 + 2
y = [1, 2, 3]
print(sum(y))</textarea>
        <div style="margin-top:0.75rem;display:flex;gap:0.5rem">
          <button class="btn btn-primary" onclick="runScan()">🔍 Scan Code</button>
          <button class="btn btn-secondary btn-sm" onclick="loadSample('clean')">Clean Sample</button>
          <button class="btn btn-secondary btn-sm" onclick="loadSample('dirty')">Dangerous Sample</button>
        </div>
      </div>
      <div class="tab-content" id="tab-file">
        <input type="file" id="fileInput" accept=".py" onchange="handleFileUpload(this)" style="margin-bottom:0.75rem;color:var(--text)">
        <div id="fileContent" style="display:none">
          <textarea class="textarea" id="fileCode" readonly style="min-height:100px"></textarea>
          <button class="btn btn-primary" style="margin-top:0.5rem" onclick="runFileScan()">🔍 Scan File</button>
        </div>
      </div>
      <div class="result-panel" id="scanResult"><div class="empty-state">Click "Scan Code" to analyze</div></div>
    </div>

    <!-- AUTH -->
    <div class="card">
      <div class="card-title"><span class="icon icon-auth">🔐</span> JWT & RBAC</div>
      <div class="input-row">
        <input type="text" id="authSubject" placeholder="Subject (e.g. chris)" value="chris">
        <select id="authRole" style="padding:0.5rem;background:#0d1117;border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.85rem">
          <option value="admin">admin</option>
          <option value="auditor">auditor</option>
          <option value="scanner" selected>scanner</option>
          <option value="viewer">viewer</option>
        </select>
        <button class="btn btn-success btn-sm" onclick="issueToken()">Issue Token</button>
      </div>
      <div class="result-panel" id="tokenResult" style="min-height:60px"><div class="empty-state">Issue a token to see result</div></div>
      <div style="margin-top:0.75rem;display:flex;gap:0.5rem">
        <input type="text" id="verifyToken" placeholder="Paste token to verify..." style="flex:1;padding:0.5rem;background:#0d1117;border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.8rem">
        <button class="btn btn-primary btn-sm" onclick="verifyToken()">Verify</button>
      </div>
      <div class="result-panel" id="verifyResult" style="min-height:60px;margin-top:0.5rem"><div class="empty-state">Verify a token to see payload</div></div>
    </div>

    <!-- AUDIT -->
    <div class="card">
      <div class="card-title"><span class="icon icon-audit">📋</span> Audit Log</div>
      <div class="input-row">
        <input type="text" id="auditEvent" placeholder="Event type (e.g. SCAN)" value="SCAN">
        <input type="text" id="auditData" placeholder='Data JSON' value='{"file":"test.py"}'>
        <button class="btn btn-success btn-sm" onclick="logEvent()">Log Event</button>
      </div>
      <div style="display:flex;gap:0.5rem;margin-bottom:0.75rem">
        <button class="btn btn-primary btn-sm" onclick="verifyChain()">🔗 Verify Chain</button>
        <button class="btn btn-secondary btn-sm" onclick="exportAudit()">📤 Export</button>
        <button class="btn btn-secondary btn-sm" onclick="clearAudit()">🗑️ Clear</button>
      </div>
      <div class="result-panel" id="auditResult" style="max-height:250px"><div class="empty-state">No audit entries yet</div></div>
    </div>

    <!-- COMPLIANCE -->
    <div class="card">
      <div class="card-title"><span class="icon icon-compliance">📊</span> Compliance Reports</div>
      <div style="display:flex;gap:0.5rem;margin-bottom:0.75rem">
        <button class="btn btn-primary btn-sm" onclick="runCompliance('soc2')">SOC 2</button>
        <button class="btn btn-primary btn-sm" onclick="runCompliance('iso27001')">ISO 27001</button>
        <button class="btn btn-primary btn-sm" onclick="runCompliance('pci')">PCI-DSS</button>
      </div>
      <div class="result-panel" id="complianceResult"><div class="empty-state">Run a compliance check</div></div>
    </div>

    <!-- AGENT -->
    <div class="card">
      <div class="card-title"><span class="icon icon-agent">🤖</span> Agent Verifier</div>
      <div class="input-row">
        <input type="text" id="agentTask" placeholder="Task ID" value="task_001">
      </div>
      <textarea class="textarea" id="agentCode" placeholder="Agent code to verify..." style="min-height:80px">print("hello world")</textarea>
      <button class="btn btn-primary" style="margin-top:0.5rem" onclick="verifyAgent()">Verify Agent Task</button>
      <div class="result-panel" id="agentResult" style="margin-top:0.75rem;min-height:60px"><div class="empty-state">Verify an agent task</div></div>
    </div>

    <!-- SEMANTIC -->
    <div class="card">
      <div class="card-title"><span class="icon icon-semantic">🔬</span> Semantic Analysis</div>
      <textarea class="textarea" id="semanticCode" placeholder="Code to analyze for obfuscation..." style="min-height:80px">x = 1 + 2</textarea>
      <button class="btn btn-primary" style="margin-top:0.5rem" onclick="runSemantic()">Analyze</button>
      <div class="result-panel" id="semanticResult" style="margin-top:0.75rem;min-height:60px"><div class="empty-state">Run semantic analysis</div></div>
    </div>
  </div>

  <div class="footer">
    VeriForge Red v1.0.0 — Hardened Formal Verification Platform — CSP7211<br>
    No eval • HMAC-Signed • Immutable Audit • SOC 2 / ISO 27001 Ready
  </div>
</div>

<script>
let stats = {scans:0, threats:0, audits:0, verified:0};

function switchTab(id, btn) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-'+id).classList.add('active');
}

function loadSample(type) {
  const clean = "x = 1 + 2\ny = [1, 2, 3]\nprint(sum(y))";
  const dirty = "import os\nimport subprocess\n\ndef run(cmd):\n    os.system(cmd)\n    subprocess.call(cmd, shell=True)\n\ndef execute(user_input):\n    eval(user_input)\n    exec(user_input)\n    code = compile(user_input, '<string>', 'exec')\n    exec(code)\n\ndef load(name):\n    return __import__(name)\n\ndef wildcard():\n    from os import *\n\ndef open_file(path):\n    return open(path).read()\n\ndef get_input():\n    return input('Enter: ')";
  document.getElementById('scanCode').value = type==='clean' ? clean : dirty;
}

function handleFileUpload(input) {
  const file = input.files[0];
  if(!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('fileCode').value = e.target.result;
    document.getElementById('fileContent').style.display = 'block';
  };
  reader.readAsText(file);
}

async function api(action, data) {
  const res = await fetch('/api/' + action, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
  return res.json();
}

async function runScan() {
  const code = document.getElementById('scanCode').value;
  const panel = document.getElementById('scanResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Scanning...</div>';
  const result = await api('scan', {code});
  stats.scans++;
  if(result.verified) stats.verified++; else stats.threats += result.findings.length;
  updateStats();
  renderScanResult(panel, result);
  if(!result.verified) document.getElementById('statusBadge').className = 'status-badge alert';
}

async function runFileScan() {
  const code = document.getElementById('fileCode').value;
  const panel = document.getElementById('scanResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Scanning file...</div>';
  const result = await api('scan', {code});
  stats.scans++;
  if(result.verified) stats.verified++; else stats.threats += result.findings.length;
  updateStats();
  renderScanResult(panel, result);
}

function renderScanResult(panel, r) {
  let cls = r.verified ? 'pass' : 'fail';
  let html = '<div style="color:' + (r.verified?'var(--success)':'var(--danger)') + ';font-weight:700;margin-bottom:0.5rem">' + (r.verified?'✅ VERIFIED CLEAN':'🚨 THREATS DETECTED') + '</div>';
  html += '<div style="color:var(--muted);font-size:0.75rem;margin-bottom:0.5rem">Hash: ' + r.code_hash + ' | Sig: ' + r.signature.substring(0,16) + '...</div>';
  if(r.findings.length > 0) {
    html += '<div style="margin-top:0.5rem"><strong style="color:var(--danger)">Findings:</strong></div>';
    r.findings.forEach(f => {
      const type = f.includes('SYNTAX') ? 'warning' : 'critical';
      html += '<div class="finding-item ' + type + '">' + (f.includes('SYNTAX')?'⚠️':'🚫') + ' ' + f + '</div>';
    });
  }
  panel.className = 'result-panel ' + cls;
  panel.innerHTML = html;
}

async function issueToken() {
  const sub = document.getElementById('authSubject').value;
  const role = document.getElementById('authRole').value;
  const panel = document.getElementById('tokenResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Issuing...</div>';
  const result = await api('auth_issue', {subject: sub, role});
  panel.innerHTML = '<div style="word-break:break-all;font-size:0.75rem;color:var(--success)">✅ Token issued:<br><br>' + result.token + '</div>';
  document.getElementById('verifyToken').value = result.token;
}

async function verifyToken() {
  const token = document.getElementById('verifyToken').value;
  const panel = document.getElementById('verifyResult');
  if(!token){panel.innerHTML='<div class="empty-state">Paste a token first</div>';return;}
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Verifying...</div>';
  const result = await api('auth_verify', {token});
  if(result.error) {
    panel.innerHTML = '<div style="color:var(--danger)">❌ ' + result.error + '</div>';
    panel.className = 'result-panel fail';
  } else {
    panel.innerHTML = '<div style="color:var(--success)">✅ Valid Token<br><br>Subject: ' + result.payload.sub + '<br>Role: ' + result.payload.role + '<br>Issued: ' + new Date(result.payload.iat*1000).toLocaleString() + '<br>Expires: ' + new Date(result.payload.exp*1000).toLocaleString() + '</div>';
    panel.className = 'result-panel pass';
  }
}

async function logEvent() {
  const type = document.getElementById('auditEvent').value;
  const dataStr = document.getElementById('auditData').value;
  let data = {};
  try { data = JSON.parse(dataStr); } catch(e) {}
  const result = await api('audit_log', {type, data});
  stats.audits++;
  updateStats();
  refreshAuditDisplay();
}

async function verifyChain() {
  const result = await api('audit_verify', {});
  const panel = document.getElementById('auditResult');
  panel.innerHTML = '<div style="color:' + (result.valid?'var(--success)':'var(--danger)') + ';font-weight:700;font-size:1rem;padding:1rem;text-align:center">' + (result.valid?'✅ CHAIN INTEGRITY VERIFIED':'🚨 CHAIN TAMPERED') + '</div>';
  panel.className = 'result-panel ' + (result.valid?'pass':'fail');
}

async function exportAudit() {
  const result = await api('audit_export', {});
  const blob = new Blob([JSON.stringify(result.entries, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'veriforge_audit.json';
  a.click();
  URL.revokeObjectURL(url);
}

async function clearAudit() {
  await api('audit_clear', {});
  stats.audits = 0;
  updateStats();
  document.getElementById('auditResult').innerHTML = '<div class="empty-state">Audit log cleared</div>';
  document.getElementById('auditResult').className = 'result-panel';
}

async function refreshAuditDisplay() {
  const result = await api('audit_export', {});
  const panel = document.getElementById('auditResult');
  if(result.entries.length === 0) {
    panel.innerHTML = '<div class="empty-state">No audit entries</div>';
    return;
  }
  let html = '<div style="color:var(--muted);font-size:0.75rem;margin-bottom:0.5rem">' + result.entries.length + ' entries</div>';
  result.entries.slice(-5).forEach(e => {
    html += '<div class="finding-item info" style="font-size:0.75rem">#' + e.seq + ' ' + e.type + ' — ' + new Date(e.ts*1000).toLocaleTimeString() + ' — HMAC: ' + e.hmac.substring(0,12) + '...</div>';
  });
  panel.innerHTML = html;
}

async function runCompliance(std) {
  const panel = document.getElementById('complianceResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Running...</div>';
  const result = await api('compliance', {standard: std});
  let html = '<div style="color:' + (result.passed?'var(--success)':'var(--danger)') + ';font-weight:700;margin-bottom:0.5rem">' + result.standard + ': ' + (result.passed?'✅ PASSED':'❌ FAILED') + '</div>';
  html += '<div style="font-size:0.8rem">';
  for(const k in result.checks) {
    const v = result.checks[k];
    html += '<div style="display:flex;justify-content:space-between;padding:0.25rem 0;border-bottom:1px solid var(--border)"><span>' + k + '</span><span style="color:' + (v?'var(--success)':'var(--danger)') + '">' + (v?'✓':'✗') + '</span></div>';
  }
  html += '</div>';
  panel.className = 'result-panel ' + (result.passed?'pass':'fail');
  panel.innerHTML = html;
}

async function verifyAgent() {
  const taskId = document.getElementById('agentTask').value;
  const code = document.getElementById('agentCode').value;
  const panel = document.getElementById('agentResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Verifying...</div>';
  const result = await api('agent_verify', {task_id: taskId, code});
  let html = '<div style="color:' + (result.verified?'var(--success)':'var(--danger)') + ';font-weight:700;margin-bottom:0.5rem">' + (result.verified?'✅ AGENT TASK VERIFIED':'🚨 AGENT TASK BLOCKED') + '</div>';
  if(result.findings.length > 0) {
    html += '<div style="margin-top:0.5rem"><strong>Findings:</strong></div>';
    result.findings.forEach(f => html += '<div class="finding-item critical">🚫 ' + f + '</div>');
  }
  html += '<div style="color:var(--muted);font-size:0.75rem;margin-top:0.5rem">Hash: ' + result.code_hash + ' | Sig: ' + result.signature.substring(0,16) + '...</div>';
  panel.className = 'result-panel ' + (result.verified?'pass':'fail');
  panel.innerHTML = html;
}

async function runSemantic() {
  const code = document.getElementById('semanticCode').value;
  const panel = document.getElementById('semanticResult');
  panel.innerHTML = '<div class="empty-state"><span class="spinner"></span> Analyzing...</div>';
  const result = await api('semantic', {code});
  let html = '<div style="color:' + (result.obfuscated?'var(--warning)':'var(--success)') + ';font-weight:700;margin-bottom:0.5rem">' + (result.obfuscated?'⚠️ OBFUSCATION DETECTED':'✅ NO OBFUSCATION') + '</div>';
  if(result.findings.length > 0) {
    result.findings.forEach(f => html += '<div class="finding-item warning">⚠️ ' + f + '</div>');
  }
  panel.className = 'result-panel ' + (result.obfuscated?'warn':'pass');
  panel.innerHTML = html;
}

function updateStats() {
  document.getElementById('statScans').textContent = stats.scans;
  document.getElementById('statThreats').textContent = stats.threats;
  document.getElementById('statAudits').textContent = stats.audits;
  document.getElementById('statVerified').textContent = stats.verified;
}

setTimeout(refreshAuditDisplay, 500);
</script>
</body>
</html>
"""

# ── HTTP Request Handler ──
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.path.startswith("/api/"):
            self.send_response(404)
            self.end_headers()
            return

        action = self.path[5:]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body) if body else {}

        result = self.handle_api(action, data)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def handle_api(self, action, data):
        try:
            if action == "scan":
                code = data.get("code", "")
                r = engine.verify_code(code)
                return {"verified": r.verified, "findings": list(r.findings), "signature": r.signature, "code_hash": r.code_hash}

            elif action == "auth_issue":
                token = auth_mgr.issue_token(data["subject"], role=data.get("role", "viewer"))
                return {"token": token}

            elif action == "auth_verify":
                try:
                    payload = auth_mgr.verify_token(data["token"])
                    return {"payload": payload}
                except Exception as e:
                    return {"error": str(e)}

            elif action == "audit_log":
                entry = audit_log.log_event(data.get("type", "EVENT"), data.get("data", {}))
                return {"seq": entry["seq"], "hmac": entry["hmac"]}

            elif action == "audit_verify":
                return {"valid": audit_log.verify_chain()}

            elif action == "audit_export":
                return {"entries": audit_log.export()}

            elif action == "audit_clear":
                audit_log._entries.clear()
                audit_log._chain_hash = "0" * 64
                return {"cleared": True}

            elif action == "compliance":
                std = data.get("standard", "soc2")
                if std == "soc2":
                    r = compliance.run_soc2_check()
                elif std == "iso27001":
                    r = compliance.run_iso27001_check()
                else:
                    r = compliance.run_pci_dss_check()
                return r

            elif action == "agent_verify":
                r = agent_verifier.verify_agent_task(data.get("task_id", "task"), {"code": data.get("code", "")})
                return r

            elif action == "semantic":
                r = SemanticAnalyzer().analyze(data.get("code", ""))
                return r

            else:
                return {"error": "Unknown action"}

        except Exception as e:
            return {"error": str(e)}


# ── Launch ──
def main():
    port = 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    url = "http://localhost:" + str(port)

    print("=" * 60)
    print("  🛡️  VeriForge Red — Desktop Dashboard")
    print("=" * 60)
    print("")
    print("  Server: " + url)
    print("  Press Ctrl+C to stop")
    print("")

    def open_browser():
        time.sleep(1.5)
        webbrowser.open(url)
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")
        print("  👋 Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()

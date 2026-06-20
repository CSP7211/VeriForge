import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';
import GradeBadge from '../components/GradeBadge';
import SeverityBadge from '../components/SeverityBadge';

const DEMO_SCANNERS = [
  { id: 'bandit', name: 'Bandit', description: 'Python security linter — detects common security issues in Python code' },
  { id: 'semgrep', name: 'Semgrep', description: 'Lightweight static analysis — finds bugs and enforces code standards' },
  { id: 'safety', name: 'Safety', description: 'Dependency vulnerability scanner — checks Python packages for known CVEs' },
  { id: 'trivy', name: 'Trivy', description: 'Comprehensive vulnerability scanner — containers, filesystem, repositories' },
  { id: 'checkov', name: 'Checkov', description: 'Infrastructure-as-Code scanner — finds misconfigurations in Terraform, CloudFormation, K8s' },
  { id: 'trufflehog', name: 'TruffleHog', description: 'Secret detector — finds exposed API keys, tokens, and credentials' },
  { id: 'codeql', name: 'CodeQL', description: 'Semantic code analysis — deep vulnerability detection using semantic queries' },
];

const DEMO_STANDARDS = [
  { id: 'soc2', name: 'SOC 2', description: 'Service Organization Control 2' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' },
  { id: 'pci_dss', name: 'PCI-DSS', description: 'Payment Card Industry Data Security Standard' },
];

export default function ScanPage() {
  const [code, setCode] = useState('');
  const [selectedScanners, setSelectedScanners] = useState(['all']);
  const [selectedStandards, setSelectedStandards] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [showJson, setShowJson] = useState(false);
  const [scanners, setScanners] = useState(DEMO_SCANNERS);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await api.getScanners();
        if (!cancelled && data.scanners) {
          setScanners(data.scanners.map((s, i) => ({
            id: s.id || s,
            name: s.name || s,
            description: s.description || DEMO_SCANNERS[i]?.description || '',
          })));
        }
      } catch {
        /* keep defaults */
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const handleScannerChange = (scannerId) => {
    if (scannerId === 'all') {
      setSelectedScanners(['all']);
      return;
    }
    setSelectedScanners((prev) => {
      const filtered = prev.filter((s) => s !== 'all');
      if (filtered.includes(scannerId)) {
        const next = filtered.filter((s) => s !== scannerId);
        return next.length === 0 ? ['all'] : next;
      }
      return [...filtered, scannerId];
    });
  };

  const handleStandardToggle = (stdId) => {
    setSelectedStandards((prev) =>
      prev.includes(stdId) ? prev.filter((s) => s !== stdId) : [...prev, stdId]
    );
  };

  const runScan = async (mode) => {
    if (!code.trim()) {
      setError('Please enter code to scan');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const payload = {
        code,
        scanners: mode === 'pipeline' ? ['all'] : selectedScanners,
        standards: selectedStandards.length > 0 ? selectedStandards : undefined,
      };
      const data = await api.runPipeline(payload);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-vf-textPrimary">Scan</h1>
        <p className="text-sm text-vf-textMuted mt-1">Run security scanners against your code</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Code Editor */}
        <div className="xl:col-span-2 vf-card flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider">
              Code Editor
            </h3>
            <span className="text-xs text-vf-textMuted">Paste your code below</span>
          </div>
          <div className="relative flex-1 min-h-[400px]">
            <textarea
              className="w-full h-full min-h-[400px] vf-input font-mono text-xs leading-5 resize-none"
              placeholder={`# Paste your code here...\n# Example:\ndef authenticate(user, password):\n    query = "SELECT * FROM users WHERE name = '%s' AND password = '%s'" % (user, password)\n    cursor.execute(query)  # SQL Injection vulnerability`}
              value={code}
              onChange={(e) => { setCode(e.target.value); setError(null); }}
            />
          </div>
        </div>

        {/* Scanner Config */}
        <div className="space-y-4">
          {/* Scanners */}
          <div className="vf-card">
            <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-3">
              Scanners
            </h3>
            <div className="space-y-2">
              <label className="flex items-start gap-3 p-2.5 rounded-lg border border-vf-border bg-vf-bg/50 cursor-pointer hover:border-vf-primary/50 transition-colors">
                <input
                  type="radio"
                  name="scanner-mode"
                  checked={selectedScanners.includes('all')}
                  onChange={() => handleScannerChange('all')}
                  className="mt-0.5 w-4 h-4 text-vf-primary"
                />
                <div>
                  <p className="text-sm font-medium text-vf-textPrimary">Run All Scanners</p>
                  <p className="text-xs text-vf-textMuted">Execute the full pipeline with all available scanners</p>
                </div>
              </label>
              <div className="border-t border-vf-border/50 pt-2 space-y-1">
                {scanners.map((scanner) => (
                  <label
                    key={scanner.id}
                    className="flex items-start gap-3 p-2 rounded-lg hover:bg-vf-surfaceHover/50 cursor-pointer transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={selectedScanners.includes(scanner.id)}
                      onChange={() => handleScannerChange(scanner.id)}
                      className="mt-0.5 w-4 h-4 rounded text-vf-primary"
                    />
                    <div>
                      <p className="text-sm font-medium text-vf-textPrimary">{scanner.name}</p>
                      <p className="text-xs text-vf-textMuted">{scanner.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Standards */}
          <div className="vf-card">
            <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-3">
              Compliance Standards
              <span className="normal-case text-vf-textMuted font-normal ml-1">(optional)</span>
            </h3>
            <div className="space-y-2">
              {DEMO_STANDARDS.map((std) => (
                <label
                  key={std.id}
                  className="flex items-start gap-3 p-2 rounded-lg hover:bg-vf-surfaceHover/50 cursor-pointer transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={selectedStandards.includes(std.id)}
                    onChange={() => handleStandardToggle(std.id)}
                    className="mt-0.5 w-4 h-4 rounded text-vf-primary"
                  />
                  <div>
                    <p className="text-sm font-medium text-vf-textPrimary">{std.name}</p>
                    <p className="text-xs text-vf-textMuted">{std.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="space-y-2">
            {error && (
              <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-2">{error}</p>
            )}
            <button
              onClick={() => runScan('pipeline')}
              disabled={loading}
              className="w-full vf-btn-primary"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Running Pipeline...
                </span>
              ) : (
                'Run Full Pipeline'
              )}
            </button>
            <button
              onClick={() => runScan('selected')}
              disabled={loading || selectedScanners.includes('all')}
              className="w-full vf-btn-secondary"
            >
              Run Selected Scanner{selectedScanners.filter(s => s !== 'all').length > 1 ? 's' : ''}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="vf-card border-vf-primary/30 animate-slide-up">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
            <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider">
              Scan Results
            </h3>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowJson(!showJson)}
                className="text-xs vf-btn-secondary py-1 px-3"
              >
                {showJson ? 'Hide JSON' : 'Show JSON'}
              </button>
              <button
                onClick={() => setResult(null)}
                className="p-1 text-vf-textMuted hover:text-vf-textPrimary transition-colors"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {!showJson ? (
            <>
              <div className="flex flex-wrap items-center gap-6 mb-6 p-4 bg-vf-bg rounded-lg border border-vf-border">
                <div>
                  <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Grade</p>
                  <GradeBadge grade={result.grade || 'F'} size="lg" />
                </div>
                <div>
                  <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Risk Score</p>
                  <p className={`text-2xl font-bold tabular-nums ${
                    (result.risk_score || 0) > 70 ? 'text-red-400' :
                    (result.risk_score || 0) > 40 ? 'text-amber-400' :
                    'text-emerald-400'
                  }`}>
                    {result.risk_score ?? 0}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Findings</p>
                  <p className="text-2xl font-bold text-vf-textPrimary tabular-nums">
                    {result.findings?.length || 0}
                  </p>
                </div>
                {result.compliance && (
                  <div>
                    <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Compliance</p>
                    <p className="text-2xl font-bold text-vf-primary tabular-nums">
                      {result.compliance.passed}/{result.compliance.total}
                    </p>
                  </div>
                )}
              </div>

              {result.findings && result.findings.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="vf-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Scanner</th>
                        <th>CWE</th>
                        <th>Line</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.findings.map((f, i) => (
                        <tr key={i}>
                          <td><SeverityBadge severity={f.severity} /></td>
                          <td className="text-vf-textPrimary max-w-xs truncate">{f.title}</td>
                          <td className="text-vf-textMuted text-xs">{f.scanner || '—'}</td>
                          <td className="font-mono text-xs">{f.cwe || '—'}</td>
                          <td className="font-mono text-xs">{f.line || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-8">
                  <p className="text-emerald-400 text-lg mb-1">No findings detected</p>
                  <p className="text-sm text-vf-textMuted">Your code passed all security checks</p>
                </div>
              )}
            </>
          ) : (
            <pre className="bg-vf-bg border border-vf-border rounded-lg p-4 text-xs font-mono text-vf-textSecondary overflow-x-auto max-h-[500px] overflow-y-auto">
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

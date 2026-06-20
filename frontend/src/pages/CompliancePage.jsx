import React, { useState } from 'react';
import { api } from '../lib/api';

const DEMO_COMPLIANCE = {
  soc2: { score: 78, passed: 23, failed: 7, total: 30, controls: [
    { id: 'CC6.1', name: 'Logical access security', description: 'Logical access to system components is restricted', passed: true },
    { id: 'CC6.2', name: 'Access removal', description: 'Access is removed upon termination', passed: true },
    { id: 'CC6.3', name: 'Access reviews', description: 'Access is reviewed periodically', passed: false },
    { id: 'CC6.4', name: 'Encryption in transit', description: 'Data is encrypted during transmission', passed: true },
    { id: 'CC6.5', name: 'Encryption at rest', description: 'Sensitive data is encrypted at rest', passed: true },
    { id: 'CC6.6', name: 'Security infrastructure', description: 'Security infrastructure is documented', passed: false },
    { id: 'CC7.1', name: 'Vulnerability detection', description: 'System vulnerabilities are detected', passed: true },
    { id: 'CC7.2', name: 'Patch management', description: 'Patches are applied in a timely manner', passed: false },
    { id: 'CC7.3', name: 'Security incident response', description: 'Security incidents are responded to', passed: true },
    { id: 'CC8.1', name: 'Change management', description: 'Changes are authorized and tested', passed: true },
  ]},
  iso27001: { score: 65, passed: 13, failed: 7, total: 20, controls: [
    { id: 'A.8.1', name: 'Asset inventory', description: 'Information assets are inventoried', passed: true },
    { id: 'A.9.1', name: 'Access control policy', description: 'Access control policy is defined', passed: true },
    { id: 'A.9.2', name: 'User access management', description: 'User access is managed', passed: false },
    { id: 'A.9.4', name: 'System access control', description: 'System access is restricted', passed: true },
    { id: 'A.10.1', name: 'Cryptographic controls', description: 'Cryptographic controls are implemented', passed: false },
    { id: 'A.12.1', name: 'Operational procedures', description: 'Operational security procedures exist', passed: true },
    { id: 'A.12.4', name: 'Logging and monitoring', description: 'Security events are logged', passed: true },
    { id: 'A.12.6', name: 'Vulnerability management', description: 'Technical vulnerabilities are managed', passed: false },
    { id: 'A.14.1', name: 'Security in development', description: 'Security is part of development', passed: true },
    { id: 'A.16.1', name: 'Incident management', description: 'Security incidents are managed', passed: false },
  ]},
  pci_dss: { score: 82, passed: 9, failed: 2, total: 11, controls: [
    { id: 'Req 1', name: 'Firewall configuration', description: 'Firewall and router standards are maintained', passed: true },
    { id: 'Req 2', name: 'Default passwords', description: 'Default passwords are changed', passed: true },
    { id: 'Req 3', name: 'Cardholder data protection', description: 'Stored cardholder data is protected', passed: true },
    { id: 'Req 4', name: 'Encryption transmission', description: 'Cardholder data is encrypted in transit', passed: true },
    { id: 'Req 5', name: 'Anti-virus', description: 'Anti-virus software is used', passed: false },
    { id: 'Req 6', name: 'Secure systems', description: 'Systems are secured against vulnerabilities', passed: true },
    { id: 'Req 7', name: 'Need-to-know access', description: 'Access is restricted to need-to-know', passed: true },
    { id: 'Req 8', name: 'User authentication', description: 'Users are uniquely identified', passed: true },
    { id: 'Req 10', name: 'Network monitoring', description: 'Network resources are monitored', passed: false },
    { id: 'Req 11', name: 'Security testing', description: 'Security systems are tested regularly', passed: true },
  ]},
};

const HISTORY = [
  { id: 1, standard: 'SOC 2', score: 78, passed: 23, failed: 7, date: '2024-01-15T10:30:00Z' },
  { id: 2, standard: 'ISO 27001', score: 65, passed: 13, failed: 7, date: '2024-01-14T16:45:00Z' },
  { id: 3, standard: 'PCI-DSS', score: 82, passed: 9, failed: 2, date: '2024-01-14T14:20:00Z' },
  { id: 4, standard: 'SOC 2', score: 72, passed: 21, failed: 9, date: '2024-01-13T09:10:00Z' },
  { id: 5, standard: 'ISO 27001', score: 60, passed: 12, failed: 8, date: '2024-01-12T11:30:00Z' },
];

function ScoreRing({ score, size = 80 }) {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444';

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1e3a5f" strokeWidth="6" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          className="transition-all duration-1000"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-lg font-bold tabular-nums" style={{ color }}>{score}</span>
      </div>
    </div>
  );
}

export default function CompliancePage() {
  const [activeStandard, setActiveStandard] = useState('soc2');
  const [checkCode, setCheckCode] = useState('');
  const [checkStandard, setCheckStandard] = useState('soc2');
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState(null);

  const standard = DEMO_COMPLIANCE[activeStandard];

  const runComplianceCheck = async () => {
    if (!checkCode.trim()) return;
    setChecking(true);
    setCheckResult(null);
    try {
      const result = await api.complianceCheck({ code: checkCode, standard: checkStandard });
      setCheckResult(result);
    } catch (err) {
      setCheckResult({ error: err.message });
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-vf-textPrimary">Compliance</h1>
        <p className="text-sm text-vf-textMuted mt-1">Track compliance against security standards</p>
      </div>

      {/* Standard cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Object.entries(DEMO_COMPLIANCE).map(([key, data]) => (
          <button
            key={key}
            onClick={() => setActiveStandard(key)}
            className={`vf-card text-left transition-all duration-200 ${
              activeStandard === key
                ? 'border-vf-primary/50 bg-vf-primary/5'
                : 'hover:border-vf-primary/30'
            }`}
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-bold text-vf-textPrimary uppercase tracking-wide">
                  {key === 'soc2' ? 'SOC 2' : key === 'iso27001' ? 'ISO 27001' : 'PCI-DSS'}
                </h3>
                <p className="text-xs text-vf-textMuted mt-0.5">
                  {data.passed}/{data.total} controls passed
                </p>
              </div>
              <ScoreRing score={data.score} size={64} />
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="text-emerald-400">{data.passed} passed</span>
              <span className="text-red-400">{data.failed} failed</span>
            </div>
          </button>
        ))}
      </div>

      {/* Controls checklist */}
      <div className="vf-card">
        <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-4">
          {activeStandard === 'soc2' ? 'SOC 2' : activeStandard === 'iso27001' ? 'ISO 27001' : 'PCI-DSS'} Controls
        </h3>
        <div className="space-y-2">
          {standard.controls.map((control) => (
            <div
              key={control.id}
              className="flex items-center gap-4 p-3 rounded-lg bg-vf-bg/50 border border-vf-border/50 hover:border-vf-border transition-colors"
            >
              <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                control.passed ? 'bg-emerald-500/10' : 'bg-red-500/10'
              }`}>
                {control.passed ? (
                  <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-vf-textMuted">{control.id}</span>
                  <span className="text-sm font-medium text-vf-textPrimary">{control.name}</span>
                </div>
                <p className="text-xs text-vf-textMuted mt-0.5">{control.description}</p>
              </div>
              <span className={`flex-shrink-0 text-xs font-medium px-2 py-0.5 rounded-full ${
                control.passed
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'bg-red-500/10 text-red-400'
              }`}>
                {control.passed ? 'Pass' : 'Fail'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Compliance check */}
      <div className="vf-card">
        <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-4">
          Run Compliance Check
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <textarea
              className="w-full h-36 vf-input font-mono text-xs resize-none"
              placeholder="Paste code to check against compliance standards..."
              value={checkCode}
              onChange={(e) => setCheckCode(e.target.value)}
            />
          </div>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-vf-textMuted uppercase tracking-wider mb-1.5">Standard</label>
              <select
                value={checkStandard}
                onChange={(e) => setCheckStandard(e.target.value)}
                className="vf-input w-full text-sm py-2"
              >
                <option value="soc2">SOC 2</option>
                <option value="iso27001">ISO 27001</option>
                <option value="pci_dss">PCI-DSS</option>
              </select>
            </div>
            <button
              onClick={runComplianceCheck}
              disabled={checking || !checkCode.trim()}
              className="w-full vf-btn-primary"
            >
              {checking ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Checking...
                </span>
              ) : (
                'Run Compliance Check'
              )}
            </button>
          </div>
        </div>
        {checkResult && !checkResult.error && (
          <div className="mt-4 p-4 bg-vf-bg rounded-lg border border-vf-border animate-slide-up">
            <div className="flex items-center gap-4 mb-3">
              <ScoreRing score={checkResult.score || 0} size={56} />
              <div>
                <p className="text-sm font-medium text-vf-textPrimary">
                  {checkResult.standard || checkStandard.toUpperCase()} Compliance
                </p>
                <p className="text-xs text-vf-textMuted">
                  {checkResult.passed || 0}/{checkResult.total || 0} controls passed
                </p>
              </div>
            </div>
            {checkResult.findings && checkResult.findings.length > 0 && (
              <div className="space-y-1">
                {checkResult.findings.map((f, i) => (
                  <div key={i} className="text-xs text-red-400">{f}</div>
                ))}
              </div>
            )}
          </div>
        )}
        {checkResult?.error && (
          <p className="mt-4 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-3">{checkResult.error}</p>
        )}
      </div>

      {/* History */}
      <div className="vf-card">
        <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-4">
          Compliance History
        </h3>
        <div className="overflow-x-auto">
          <table className="vf-table">
            <thead>
              <tr>
                <th>Standard</th>
                <th>Score</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {HISTORY.map((h) => (
                <tr key={h.id}>
                  <td className="font-medium text-vf-textPrimary">{h.standard}</td>
                  <td>
                    <span className={`font-bold tabular-nums ${
                      h.score >= 80 ? 'text-emerald-400' : h.score >= 60 ? 'text-amber-400' : 'text-red-400'
                    }`}>{h.score}</span>
                  </td>
                  <td className="text-emerald-400 tabular-nums">{h.passed}</td>
                  <td className="text-red-400 tabular-nums">{h.failed}</td>
                  <td className="text-vf-textMuted text-xs">
                    {new Date(h.date).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

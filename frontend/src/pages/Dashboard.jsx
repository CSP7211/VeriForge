import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';
import StatCard from '../components/StatCard';
import GradeBadge from '../components/GradeBadge';
import SeverityBadge from '../components/SeverityBadge';

const DEMO_STATS = {
  projects: 12,
  total_scans: 156,
  open_findings: 847,
  critical_findings: 23,
};

const DEMO_SCANS = [
  { id: 'scan-001', scanner: 'Full Pipeline', grade: 'B', risk_score: 72, findings_count: 34, created_at: '2024-01-15T10:30:00Z' },
  { id: 'scan-002', scanner: 'Bandit', grade: 'A', risk_score: 15, findings_count: 3, created_at: '2024-01-15T09:15:00Z' },
  { id: 'scan-003', scanner: 'Semgrep', grade: 'C', risk_score: 68, findings_count: 56, created_at: '2024-01-14T16:45:00Z' },
  { id: 'scan-004', scanner: 'Safety', grade: 'A+', risk_score: 5, findings_count: 0, created_at: '2024-01-14T14:20:00Z' },
  { id: 'scan-005', scanner: 'Full Pipeline', grade: 'D', risk_score: 89, findings_count: 127, created_at: '2024-01-14T11:00:00Z' },
];

const GRADE_DISTRIBUTION = { 'A+': 3, 'A': 4, 'B': 2, 'C': 1, 'D': 1, 'F': 1 };
const SEVERITY_DISTRIBUTION = { critical: 23, high: 87, medium: 245, low: 412, info: 189 };

export default function Dashboard() {
  const [stats, setStats] = useState(DEMO_STATS);
  const [recentScans, setRecentScans] = useState(DEMO_SCANS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [quickCode, setQuickCode] = useState('');
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickResult, setQuickResult] = useState(null);
  const [quickError, setQuickError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await api.getStats();
        if (!cancelled) {
          setStats(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const handleQuickScan = async () => {
    if (!quickCode.trim()) return;
    setQuickLoading(true);
    setQuickError(null);
    setQuickResult(null);
    try {
      const result = await api.runPipeline({
        code: quickCode,
        scanners: ['all'],
      });
      setQuickResult(result);
    } catch (err) {
      setQuickError(err.message);
    } finally {
      setQuickLoading(false);
    }
  };

  const maxGrade = Math.max(...Object.values(GRADE_DISTRIBUTION));
  const maxSeverity = Math.max(...Object.values(SEVERITY_DISTRIBUTION));

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-vf-textPrimary">Dashboard</h1>
        <p className="text-sm text-vf-textMuted mt-1">Overview of your security posture</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Projects"
          value={stats.projects ?? '—'}
          subtitle="Active repositories"
          icon="📁"
          color="blue"
        />
        <StatCard
          title="Total Scans"
          value={stats.total_scans ?? '—'}
          subtitle="Across all projects"
          icon="🔍"
          color="emerald"
        />
        <StatCard
          title="Open Findings"
          value={stats.open_findings ?? '—'}
          subtitle="Require attention"
          icon="⚠️"
          color="amber"
        />
        <StatCard
          title="Critical Findings"
          value={stats.critical_findings ?? '—'}
          subtitle="Immediate action needed"
          icon="🚨"
          color="red"
        />
      </div>

      {/* Charts + Quick Scan */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Grade Distribution */}
        <div className="vf-card">
          <h3 className="text-sm font-semibold text-vf-textSecondary mb-4 uppercase tracking-wider">
            Grade Distribution
          </h3>
          <div className="space-y-3">
            {Object.entries(GRADE_DISTRIBUTION).map(([grade, count]) => (
              <div key={grade} className="flex items-center gap-3">
                <GradeBadge grade={grade} />
                <div className="flex-1 h-2 bg-vf-bg rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${(count / maxGrade) * 100}%`,
                      backgroundColor: {
                        'A+': '#10b981', 'A': '#22c55e', 'B': '#84cc16',
                        'C': '#eab308', 'D': '#f97316', 'F': '#dc2626',
                      }[grade],
                    }}
                  />
                </div>
                <span className="text-xs text-vf-textMuted w-6 text-right tabular-nums">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="vf-card">
          <h3 className="text-sm font-semibold text-vf-textSecondary mb-4 uppercase tracking-wider">
            Severity Distribution
          </h3>
          <div className="space-y-3">
            {Object.entries(SEVERITY_DISTRIBUTION).map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-3">
                <SeverityBadge severity={sev} />
                <div className="flex-1 h-2 bg-vf-bg rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${(count / maxSeverity) * 100}%`,
                      backgroundColor: {
                        critical: '#dc2626', high: '#ef4444', medium: '#f59e0b',
                        low: '#3b82f6', info: '#6b7280',
                      }[sev],
                    }}
                  />
                </div>
                <span className="text-xs text-vf-textMuted w-8 text-right tabular-nums">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Scan */}
        <div className="vf-card">
          <h3 className="text-sm font-semibold text-vf-textSecondary mb-4 uppercase tracking-wider">
            Quick Scan
          </h3>
          <textarea
            className="w-full h-28 vf-input font-mono text-xs resize-none"
            placeholder="Paste code snippet to analyze..."
            value={quickCode}
            onChange={(e) => setQuickCode(e.target.value)}
          />
          <button
            onClick={handleQuickScan}
            disabled={quickLoading || !quickCode.trim()}
            className="w-full mt-3 vf-btn-primary text-sm py-2"
          >
            {quickLoading ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Analyzing...
              </span>
            ) : (
              'Run Pipeline'
            )}
          </button>
          {quickError && (
            <p className="mt-2 text-xs text-red-400">{quickError}</p>
          )}
        </div>
      </div>

      {/* Quick Scan Results */}
      {quickResult && (
        <div className="vf-card border-vf-primary/30 animate-slide-up">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider">
              Scan Results
            </h3>
            <button
              onClick={() => setQuickResult(null)}
              className="p-1 text-vf-textMuted hover:text-vf-textPrimary transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="flex items-center gap-6 mb-4">
            <div>
              <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Grade</p>
              <GradeBadge grade={quickResult.grade || 'F'} size="lg" />
            </div>
            <div>
              <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Risk Score</p>
              <p className={`text-2xl font-bold tabular-nums ${
                (quickResult.risk_score || 0) > 70 ? 'text-red-400' :
                (quickResult.risk_score || 0) > 40 ? 'text-amber-400' :
                'text-emerald-400'
              }`}>
                {quickResult.risk_score ?? 0}
              </p>
            </div>
            <div>
              <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Findings</p>
              <p className="text-2xl font-bold text-vf-textPrimary tabular-nums">
                {quickResult.findings?.length || 0}
              </p>
            </div>
          </div>
          {quickResult.findings && quickResult.findings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="vf-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>CWE</th>
                    <th>Line</th>
                  </tr>
                </thead>
                <tbody>
                  {quickResult.findings.map((f, i) => (
                    <tr key={i}>
                      <td><SeverityBadge severity={f.severity} /></td>
                      <td className="text-vf-textPrimary">{f.title}</td>
                      <td className="font-mono text-xs">{f.cwe || '—'}</td>
                      <td className="font-mono text-xs">{f.line || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Recent Scans */}
      <div className="vf-card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider">
            Recent Scans
          </h3>
          <a href="#/scan" className="text-xs text-vf-primary hover:text-vf-primaryGlow transition-colors">
            New Scan →
          </a>
        </div>
        <div className="overflow-x-auto">
          <table className="vf-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Scanner</th>
                <th>Grade</th>
                <th>Risk Score</th>
                <th>Findings</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan) => (
                <tr key={scan.id}>
                  <td className="font-mono text-xs">{scan.id}</td>
                  <td className="text-vf-textPrimary">{scan.scanner}</td>
                  <td><GradeBadge grade={scan.grade} /></td>
                  <td>
                    <span className={`tabular-nums font-medium ${
                      scan.risk_score > 70 ? 'text-red-400' :
                      scan.risk_score > 40 ? 'text-amber-400' :
                      'text-emerald-400'
                    }`}>
                      {scan.risk_score}
                    </span>
                  </td>
                  <td className="tabular-nums">{scan.findings_count}</td>
                  <td className="text-vf-textMuted text-xs">
                    {new Date(scan.created_at).toLocaleDateString()}
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

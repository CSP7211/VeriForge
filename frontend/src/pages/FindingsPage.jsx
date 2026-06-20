import React, { useState, useEffect, useMemo } from 'react';
import { api } from '../lib/api';
import FindingRow from '../components/FindingRow';
import SeverityBadge from '../components/SeverityBadge';

const DEMO_FINDINGS = [
  { id: 1, title: 'SQL Injection in authenticate()', severity: 'critical', cwe: 'CWE-89', line: 42, status: 'open', scanner: 'Bandit', matched: "query = \"SELECT * FROM users WHERE name = '%s'\" % user", fix: "query = \"SELECT * FROM users WHERE name = ?\"\ncursor.execute(query, (user,))" },
  { id: 2, title: 'Hardcoded API key detected', severity: 'high', cwe: 'CWE-798', line: 15, status: 'open', scanner: 'TruffleHog', matched: 'API_KEY = "sk-live-abc123xyz789"', fix: 'API_KEY = os.environ.get("API_KEY")' },
  { id: 3, title: 'Use of eval() with user input', severity: 'critical', cwe: 'CWE-95', line: 78, status: 'open', scanner: 'Bandit', matched: 'result = eval(user_input)', fix: 'import ast\nresult = ast.literal_eval(user_input)' },
  { id: 4, title: 'Insecure deserialization', severity: 'high', cwe: 'CWE-502', line: 103, status: 'open', scanner: 'Semgrep', matched: 'data = pickle.loads(untrusted_data)', fix: 'Use json.loads() or a safe serialization format' },
  { id: 5, title: 'Missing CSRF protection', severity: 'medium', cwe: 'CWE-352', line: 56, status: 'open', scanner: 'Semgrep', matched: '@app.route("/transfer", methods=["POST"])', fix: 'Add @csrf_exempt decorator or use Flask-WTF CSRF protection' },
  { id: 6, title: 'Weak password hashing', severity: 'high', cwe: 'CWE-916', line: 32, status: 'open', scanner: 'Bandit', matched: 'hash = hashlib.md5(password.encode()).hexdigest()', fix: 'Use bcrypt or Argon2 for password hashing' },
  { id: 7, title: 'Debug mode enabled', severity: 'medium', cwe: 'CWE-489', line: 1, status: 'resolved', scanner: 'Bandit', matched: 'DEBUG = True', fix: 'DEBUG = os.environ.get("DEBUG", "False") == "True"' },
  { id: 8, title: 'Missing input validation', severity: 'low', cwe: 'CWE-20', line: 88, status: 'false_positive', scanner: 'Semgrep', matched: 'user_id = request.args.get("id")', fix: 'user_id = int(request.args.get("id", 0))' },
  { id: 9, title: 'Open redirect vulnerability', severity: 'medium', cwe: 'CWE-601', line: 67, status: 'open', scanner: 'Bandit', matched: 'return redirect(request.args.get("next"))', fix: 'Use url_for() or a whitelist of allowed URLs' },
  { id: 10, title: 'Information exposure through error message', severity: 'low', cwe: 'CWE-209', line: 120, status: 'accepted', scanner: 'Semgrep', matched: 'return jsonify({"error": str(e)})', fix: 'return jsonify({"error": "Internal server error"}), 500' },
  { id: 11, title: 'Use of deprecated cryptographic function', severity: 'medium', cwe: 'CWE-327', line: 45, status: 'open', scanner: 'Safety', matched: 'cipher = DES.new(key, DES.MODE_ECB)', fix: 'Use AES-GCM from cryptography library' },
  { id: 12, title: 'Path traversal vulnerability', severity: 'high', cwe: 'CWE-22', line: 91, status: 'open', scanner: 'Semgrep', matched: 'filepath = "/data/" + filename', fix: 'Use os.path.join() with path normalization' },
];

const STATUS_TABS = [
  { key: 'all', label: 'All' },
  { key: 'open', label: 'Open' },
  { key: 'resolved', label: 'Resolved' },
  { key: 'false_positive', label: 'False Positive' },
  { key: 'accepted', label: 'Accepted' },
];

const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

export default function FindingsPage() {
  const [findings, setFindings] = useState(DEMO_FINDINGS);
  const [statusTab, setStatusTab] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await api.getFindings();
        if (!cancelled && data.findings) {
          setFindings(data.findings);
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchStatus = statusTab === 'all' || f.status === statusTab;
      const matchSeverity = severityFilter === 'all' || f.severity === severityFilter;
      const matchSearch = !searchQuery ||
        f.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.cwe?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.scanner?.toLowerCase().includes(searchQuery.toLowerCase());
      return matchStatus && matchSeverity && matchSearch;
    });
  }, [findings, statusTab, severityFilter, searchQuery]);

  const handleStatusChange = async (id, newStatus) => {
    try {
      await api.updateFinding(id, { status: newStatus });
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? { ...f, status: newStatus } : f))
      );
    } catch {
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? { ...f, status: newStatus } : f))
      );
    }
  };

  const statusCounts = useMemo(() => {
    const counts = { all: findings.length, open: 0, resolved: 0, false_positive: 0, accepted: 0 };
    findings.forEach((f) => { if (counts[f.status] !== undefined) counts[f.status]++; });
    return counts;
  }, [findings]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-vf-textPrimary">Findings</h1>
        <p className="text-sm text-vf-textMuted mt-1">Review and manage security findings</p>
      </div>

      {/* Status tabs */}
      <div className="flex flex-wrap gap-2">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setStatusTab(tab.key)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 border ${
              statusTab === tab.key
                ? 'bg-vf-primary/15 text-vf-primaryGlow border-vf-primary/40'
                : 'bg-vf-surface text-vf-textSecondary border-vf-border hover:text-vf-textPrimary hover:border-vf-primary/30'
            }`}
          >
            {tab.label}
            <span className={`ml-2 text-xs tabular-nums ${
              statusTab === tab.key ? 'text-vf-primary' : 'text-vf-textMuted'
            }`}>
              {statusCounts[tab.key] || 0}
            </span>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-vf-textMuted uppercase tracking-wider">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="vf-input py-1.5 text-sm w-36"
          >
            {SEVERITY_FILTERS.map((s) => (
              <option key={s} value={s}>{s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-vf-textMuted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings..."
              className="vf-input pl-9 py-1.5 text-sm w-full"
            />
          </div>
        </div>
      </div>

      {/* Findings table */}
      <div className="vf-card overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="text-center py-12">
            <svg className="w-12 h-12 text-vf-textMuted mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-vf-textSecondary font-medium">No findings match your filters</p>
            <p className="text-sm text-vf-textMuted mt-1">Try adjusting your search or filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="vf-table">
              <thead>
                <tr>
                  <th className="w-28">Severity</th>
                  <th>Title</th>
                  <th className="w-24">CWE</th>
                  <th className="w-16">Line</th>
                  <th className="w-28">Status</th>
                  <th className="w-20">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    onStatusChange={handleStatusChange}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Summary footer */}
      <div className="flex flex-wrap items-center justify-between gap-4 text-xs text-vf-textMuted">
        <p>Showing {filteredFindings.length} of {findings.length} findings</p>
        <div className="flex items-center gap-4">
          {['critical', 'high', 'medium', 'low'].map((sev) => {
            const count = findings.filter((f) => f.severity === sev && f.status === 'open').length;
            return (
              <span key={sev} className="flex items-center gap-1.5">
                <SeverityBadge severity={sev} />
                <span className="tabular-nums">{count} open</span>
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

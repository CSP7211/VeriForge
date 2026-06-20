import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';
import GradeBadge from '../components/GradeBadge';

const DEMO_PROJECTS = [
  { id: 1, name: 'payment-service', description: 'Payment processing microservice handling transactions', grade: 'B', risk_score: 62, last_scan: '2024-01-15T10:30:00Z', scan_count: 45, open_findings: 34 },
  { id: 2, name: 'auth-gateway', description: 'Authentication gateway with OAuth2 and SAML support', grade: 'A', risk_score: 28, last_scan: '2024-01-15T09:15:00Z', scan_count: 67, open_findings: 12 },
  { id: 3, name: 'user-dashboard', description: 'React frontend for user account management', grade: 'C', risk_score: 74, last_scan: '2024-01-14T16:45:00Z', scan_count: 23, open_findings: 89 },
  { id: 4, name: 'notification-engine', description: 'Email and push notification service', grade: 'A+', risk_score: 8, last_scan: '2024-01-14T14:20:00Z', scan_count: 12, open_findings: 1 },
  { id: 5, name: 'data-pipeline', description: 'ETL pipeline for analytics and reporting', grade: 'D', risk_score: 85, last_scan: '2024-01-13T11:00:00Z', scan_count: 9, open_findings: 156 },
  { id: 6, name: 'inventory-service', description: 'Product catalog and inventory management', grade: 'B', risk_score: 55, last_scan: '2024-01-12T08:30:00Z', scan_count: 31, open_findings: 23 },
];

const DEMO_SCAN_HISTORY = [
  { id: 's1', scanner: 'Full Pipeline', grade: 'B', risk_score: 62, findings: 34, date: '2024-01-15T10:30:00Z' },
  { id: 's2', scanner: 'Semgrep', grade: 'C', risk_score: 71, findings: 67, date: '2024-01-14T16:45:00Z' },
  { id: 's3', scanner: 'Bandit', grade: 'A', risk_score: 25, findings: 5, date: '2024-01-14T10:00:00Z' },
  { id: 's4', scanner: 'Full Pipeline', grade: 'C', risk_score: 68, findings: 45, date: '2024-01-13T09:30:00Z' },
  { id: 's5', scanner: 'Safety', grade: 'A+', risk_score: 5, findings: 0, date: '2024-01-12T14:00:00Z' },
];

export default function ProjectsPage() {
  const [projects, setProjects] = useState(DEMO_PROJECTS);
  const [showModal, setShowModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [form, setForm] = useState({ name: '', description: '' });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await api.getProjects();
        if (!cancelled && data.projects) {
          setProjects(data.projects);
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

  const handleCreateProject = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) return;
    try {
      const result = await api.createProject(form);
      const newProject = result.project || { ...form, id: Date.now(), grade: 'N/A', risk_score: 0, last_scan: null, scan_count: 0, open_findings: 0 };
      setProjects((prev) => [newProject, ...prev]);
      setForm({ name: '', description: '' });
      setShowModal(false);
    } catch {
      const newProject = { ...form, id: Date.now(), grade: 'N/A', risk_score: 0, last_scan: null, scan_count: 0, open_findings: 0 };
      setProjects((prev) => [newProject, ...prev]);
      setForm({ name: '', description: '' });
      setShowModal(false);
    }
  };

  if (selectedProject) {
    const project = projects.find((p) => p.id === selectedProject) || DEMO_PROJECTS[0];
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setSelectedProject(null)}
            className="p-2 text-vf-textMuted hover:text-vf-textPrimary hover:bg-vf-surfaceHover rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
          </button>
          <div>
            <h1 className="text-2xl font-bold text-vf-textPrimary">{project.name}</h1>
            <p className="text-sm text-vf-textMuted">{project.description}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="vf-card text-center">
            <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Grade</p>
            <div className="flex justify-center"><GradeBadge grade={project.grade || 'N/A'} size="lg" /></div>
          </div>
          <div className="vf-card text-center">
            <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Risk Score</p>
            <p className={`text-2xl font-bold tabular-nums ${
              (project.risk_score || 0) > 70 ? 'text-red-400' :
              (project.risk_score || 0) > 40 ? 'text-amber-400' :
              'text-emerald-400'
            }`}>{project.risk_score || 0}</p>
          </div>
          <div className="vf-card text-center">
            <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Scans</p>
            <p className="text-2xl font-bold text-vf-textPrimary tabular-nums">{project.scan_count || 0}</p>
          </div>
          <div className="vf-card text-center">
            <p className="text-xs text-vf-textMuted uppercase tracking-wider mb-1">Open Findings</p>
            <p className="text-2xl font-bold text-red-400 tabular-nums">{project.open_findings || 0}</p>
          </div>
        </div>

        <div className="vf-card">
          <h3 className="text-sm font-semibold text-vf-textSecondary uppercase tracking-wider mb-4">
            Scan History
          </h3>
          <div className="overflow-x-auto">
            <table className="vf-table">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Scanner</th>
                  <th>Grade</th>
                  <th>Risk Score</th>
                  <th>Findings</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {DEMO_SCAN_HISTORY.map((scan) => (
                  <tr key={scan.id}>
                    <td className="font-mono text-xs">{scan.id}</td>
                    <td className="text-vf-textPrimary">{scan.scanner}</td>
                    <td><GradeBadge grade={scan.grade} /></td>
                    <td className={`tabular-nums font-medium ${
                      scan.risk_score > 70 ? 'text-red-400' : scan.risk_score > 40 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>{scan.risk_score}</td>
                    <td className="tabular-nums">{scan.findings}</td>
                    <td className="text-vf-textMuted text-xs">{new Date(scan.date).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-vf-textPrimary">Projects</h1>
          <p className="text-sm text-vf-textMuted mt-1">Manage your repositories and applications</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="vf-btn-primary flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Project
        </button>
      </div>

      {projects.length === 0 ? (
        <div className="text-center py-12 vf-card">
          <p className="text-vf-textSecondary mb-3">No projects yet</p>
          <button onClick={() => setShowModal(true)} className="vf-btn-primary text-sm">
            Create your first project
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {projects.map((project) => (
            <button
              key={project.id}
              onClick={() => setSelectedProject(project.id)}
              className="vf-card text-left hover:border-vf-primary/40 transition-all duration-200 group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1 min-w-0">
                  <h3 className="font-bold text-vf-textPrimary group-hover:text-vf-primaryGlow transition-colors truncate">
                    {project.name}
                  </h3>
                  <p className="text-xs text-vf-textMuted mt-0.5 line-clamp-2">{project.description}</p>
                </div>
                <GradeBadge grade={project.grade || 'N/A'} />
              </div>
              <div className="flex items-center gap-4 text-xs text-vf-textMuted mt-4 pt-3 border-t border-vf-border/50">
                <span className="flex items-center gap-1">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                  {project.scan_count || 0} scans
                </span>
                <span className="flex items-center gap-1 text-red-400">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  {project.open_findings || 0} open
                </span>
                {project.last_scan && (
                  <span className="ml-auto text-vf-textMuted">
                    {new Date(project.last_scan).toLocaleDateString()}
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* New Project Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-vf-surface border border-vf-border rounded-2xl p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-vf-textPrimary">New Project</h2>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 text-vf-textMuted hover:text-vf-textPrimary transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleCreateProject} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                  Project Name
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                  className="vf-input"
                  placeholder="e.g., payment-service"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                  Description
                </label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
                  className="vf-input h-20 resize-none"
                  placeholder="Brief description of the project..."
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="vf-btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" className="vf-btn-primary">
                  Create Project
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

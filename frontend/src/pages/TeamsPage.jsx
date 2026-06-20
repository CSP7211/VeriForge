import React, { useState, useEffect } from 'react';
import { api } from '../lib/api';

const DEMO_TEAMS = [
  { id: 1, name: 'Security Engineering', slug: 'sec-eng', member_count: 8, members: ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'henry'] },
  { id: 2, name: 'Platform Team', slug: 'platform', member_count: 5, members: ['ivan', 'judy', 'karl', 'laura', 'mike'] },
  { id: 3, name: 'Application Security', slug: 'appsec', member_count: 4, members: ['nancy', 'oscar', 'peter', 'quinn'] },
  { id: 4, name: 'DevOps', slug: 'devops', member_count: 6, members: ['rachel', 'steve', 'tom', 'ursula', 'victor', 'wendy'] },
  { id: 5, name: 'Compliance', slug: 'compliance', member_count: 3, members: ['xander', 'yara', 'zack'] },
];

export default function TeamsPage() {
  const [teams, setTeams] = useState(DEMO_TEAMS);
  const [showModal, setShowModal] = useState(false);
  const [expandedTeam, setExpandedTeam] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [form, setForm] = useState({ name: '', slug: '' });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await api.getTeams();
        if (!cancelled && data.teams) {
          setTeams(data.teams);
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

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) return;
    const slug = form.slug || form.name.toLowerCase().replace(/\s+/g, '-');
    try {
      const result = await api.createTeam({ ...form, slug });
      const newTeam = result.team || { ...form, slug, id: Date.now(), member_count: 0, members: [] };
      setTeams((prev) => [newTeam, ...prev]);
      setForm({ name: '', slug: '' });
      setShowModal(false);
    } catch {
      const newTeam = { ...form, slug, id: Date.now(), member_count: 0, members: [] };
      setTeams((prev) => [newTeam, ...prev]);
      setForm({ name: '', slug: '' });
      setShowModal(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-vf-textPrimary">Teams</h1>
          <p className="text-sm text-vf-textMuted mt-1">Manage teams and team members</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="vf-btn-primary flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Create Team
        </button>
      </div>

      {teams.length === 0 ? (
        <div className="text-center py-12 vf-card">
          <p className="text-vf-textSecondary mb-3">No teams yet</p>
          <button onClick={() => setShowModal(true)} className="vf-btn-primary text-sm">
            Create your first team
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {teams.map((team) => {
            const isExpanded = expandedTeam === team.id;
            return (
              <div
                key={team.id}
                className="vf-card transition-all duration-200"
              >
                <button
                  onClick={() => setExpandedTeam(isExpanded ? null : team.id)}
                  className="w-full text-left"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-vf-primary/10 border border-vf-primary/30 flex items-center justify-center">
                        <svg className="w-5 h-5 text-vf-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                      </div>
                      <div>
                        <h3 className="font-bold text-vf-textPrimary">{team.name}</h3>
                        <p className="text-xs font-mono text-vf-textMuted">@{team.slug}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-vf-textMuted tabular-nums">
                        {team.member_count || (team.members?.length || 0)} members
                      </span>
                      <svg
                        className={`w-4 h-4 text-vf-textMuted transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                        fill="none" stroke="currentColor" viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                  </div>
                </button>

                {isExpanded && team.members && (
                  <div className="mt-4 pt-4 border-t border-vf-border/50 animate-slide-up">
                    <p className="text-xs font-semibold text-vf-textMuted uppercase tracking-wider mb-2">
                      Members
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {team.members.map((member, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 px-2.5 py-1.5 bg-vf-bg rounded-lg border border-vf-border/50"
                        >
                          <div className="w-5 h-5 rounded-full bg-vf-primary/20 flex items-center justify-center text-vf-primary text-xs font-bold">
                            {member.charAt(0).toUpperCase()}
                          </div>
                          <span className="text-xs text-vf-textSecondary">{member}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Create Team Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-vf-surface border border-vf-border rounded-2xl p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-vf-textPrimary">Create Team</h2>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 text-vf-textMuted hover:text-vf-textPrimary transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleCreateTeam} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                  Team Name
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => {
                    setForm((prev) => ({
                      ...prev,
                      name: e.target.value,
                      slug: prev.slug || e.target.value.toLowerCase().replace(/\s+/g, '-'),
                    }));
                  }}
                  className="vf-input"
                  placeholder="e.g., Security Engineering"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                  Slug
                </label>
                <input
                  type="text"
                  value={form.slug}
                  onChange={(e) => setForm((prev) => ({ ...prev, slug: e.target.value }))}
                  className="vf-input font-mono text-sm"
                  placeholder="e.g., security-engineering"
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
                  Create Team
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

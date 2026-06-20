import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

export default function LoginModal({ onClose }) {
  const [tab, setTab] = useState('login');
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [localError, setLocalError] = useState(null);
  const { login, register, isLoading, error } = useAuth();

  const handleChange = (e) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
    setLocalError(null);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!form.username || !form.password) {
      setLocalError('Please fill in all fields');
      return;
    }
    const success = await login({ username: form.username, password: form.password });
    if (success) {
      onClose();
      window.location.reload();
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!form.username || !form.email || !form.password) {
      setLocalError('Please fill in all fields');
      return;
    }
    if (form.password !== form.confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }
    if (form.password.length < 6) {
      setLocalError('Password must be at least 6 characters');
      return;
    }
    const success = await register({
      username: form.username,
      email: form.email,
      password: form.password,
    });
    if (success) {
      onClose();
      window.location.reload();
    }
  };

  const displayError = localError || error;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-md bg-vf-surface border border-vf-border rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-bold text-vf-textPrimary">VeriForge</h2>
            <p className="text-sm text-vf-textMuted mt-0.5">Secure Code Analysis Platform</p>
          </div>
          <button
            onClick={onClose}
            className="text-vf-textMuted hover:text-vf-textPrimary transition-colors p-1"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex mb-6 bg-vf-bg rounded-lg p-1">
          <button
            onClick={() => { setTab('login'); setLocalError(null); }}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition-all duration-200 ${
              tab === 'login'
                ? 'bg-vf-primary text-white'
                : 'text-vf-textMuted hover:text-vf-textSecondary'
            }`}
          >
            Sign In
          </button>
          <button
            onClick={() => { setTab('register'); setLocalError(null); }}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition-all duration-200 ${
              tab === 'register'
                ? 'bg-vf-primary text-white'
                : 'text-vf-textMuted hover:text-vf-textSecondary'
            }`}
          >
            Register
          </button>
        </div>

        {displayError && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
            {displayError}
          </div>
        )}

        {tab === 'login' ? (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                type="text"
                name="username"
                value={form.username}
                onChange={handleChange}
                className="vf-input"
                placeholder="Enter username"
                autoComplete="username"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                className="vf-input"
                placeholder="Enter password"
                autoComplete="current-password"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full vf-btn-primary py-2.5"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Signing in...
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <input
                type="text"
                name="username"
                value={form.username}
                onChange={handleChange}
                className="vf-input"
                placeholder="Choose a username"
                autoComplete="username"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Email
              </label>
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                className="vf-input"
                placeholder="Enter email address"
                autoComplete="email"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                className="vf-input"
                placeholder="Choose a password"
                autoComplete="new-password"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-vf-textSecondary mb-1.5 uppercase tracking-wider">
                Confirm Password
              </label>
              <input
                type="password"
                name="confirmPassword"
                value={form.confirmPassword}
                onChange={handleChange}
                className="vf-input"
                placeholder="Confirm password"
                autoComplete="new-password"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full vf-btn-primary py-2.5"
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Creating account...
                </span>
              ) : (
                'Create Account'
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

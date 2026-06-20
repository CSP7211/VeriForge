const BASE = 'http://localhost:8000/api';

async function request(path, options = {}) {
  const url = `${BASE}${path}`;
  const token = localStorage.getItem('token');

  const config = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);

    if (response.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.hash = '#/';
      window.location.reload();
      throw new Error('Unauthorized');
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || errorData.message || `HTTP ${response.status}`);
    }

    const text = await response.text();
    if (!text) return {};
    return JSON.parse(text);
  } catch (error) {
    if (error.message === 'Unauthorized') throw error;
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error('Cannot connect to API server. Please ensure the backend is running.');
    }
    throw error;
  }
}

export const api = {
  // Auth
  login: (credentials) => request('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  }),

  register: (data) => request('/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  // Stats
  getStats: () => request('/stats'),

  // Projects
  getProjects: () => request('/projects'),
  createProject: (data) => request('/projects', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  // Scans
  getScans: () => request('/scans'),
  createScan: (data) => request('/scans', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  // Findings
  getFindings: (status) => request(`/findings${status ? `?status=${status}` : ''}`),
  updateFinding: (id, data) => request(`/findings/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  }),

  // Scanners
  getScanners: () => request('/scanners'),

  // Pipeline
  runPipeline: (data) => request('/pipeline', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  // Compliance
  complianceCheck: (data) => request('/compliance', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  // Teams
  getTeams: () => request('/teams'),
  createTeam: (data) => request('/teams', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
};

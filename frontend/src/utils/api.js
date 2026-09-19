/* Paradox — Backend API Client */

import { API_BASE } from './constants';

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`API Error: ${res.status}`);
  return res.json();
}

export const api = {
  startScan: (targetUrl, scanModes) =>
    request('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ target_url: targetUrl, scan_modes: scanModes }),
    }),

  getScans: () => request('/api/scans'),

  getScan: (scanId) => request(`/api/scans/${scanId}`),

  deleteScan: (scanId) => request(`/api/scans/${scanId}`, { method: 'DELETE' }),

  getStats: () => request('/api/stats'),

  search: (query) => request(`/api/search?q=${encodeURIComponent(query)}`),

  getCompliance: (scanId) => request(`/api/compliance/${scanId}`),

  chatWithAgent: (message) =>
    request('/api/agent/chat', {
      method: 'POST',
      body: JSON.stringify({ message, agent_type: 'defender' }),
    }),
};

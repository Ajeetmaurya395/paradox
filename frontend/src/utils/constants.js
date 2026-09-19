/* Paradox — Color and configuration constants */

export const API_BASE = 'http://localhost:8000';
export const WS_BASE = 'ws://localhost:8000';

export const COLORS = {
  cyan: '#00d4ff',
  purple: '#8b5cf6',
  amber: '#f59e0b',
  danger: '#ef4444',
  success: '#10b981',
  warning: '#f59e0b',
  info: '#6366f1',
};

export const MODE_CONFIG = {
  security: {
    label: 'Security',
    icon: '🔒',
    color: COLORS.cyan,
    bgClass: 'mode-security-bg',
    textClass: 'mode-security',
  },
  privacy: {
    label: 'Privacy',
    icon: '👁️',
    color: COLORS.purple,
    bgClass: 'mode-privacy-bg',
    textClass: 'mode-privacy',
  },
  agent: {
    label: 'AI Agent',
    icon: '🤖',
    color: COLORS.amber,
    bgClass: 'mode-agent-bg',
    textClass: 'mode-agent',
  },
};

export const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ef4444', bgClass: 'badge-critical' },
  high: { label: 'High', color: '#f97316', bgClass: 'badge-high' },
  medium: { label: 'Medium', color: '#f59e0b', bgClass: 'badge-medium' },
  low: { label: 'Low', color: '#6366f1', bgClass: 'badge-low' },
  info: { label: 'Info', color: '#94a3b8', bgClass: 'badge-info' },
};

export const AWS_TOOLS = [
  { name: 'Strands Agents SDK', icon: '🧠', category: 'Agents and AI' },
  { name: 'PartyRock', icon: '🎮', category: 'Agents and AI' },
  { name: 'Finch', icon: '🐧', category: 'Containers' },
  { name: 'EKS Distro', icon: '☸️', category: 'Kubernetes' },
  { name: 'EKS Anywhere', icon: '☸️', category: 'Kubernetes' },
  { name: 'SAM CLI', icon: '🚀', category: 'Serverless' },
  { name: 'LocalStack', icon: '🖥️', category: 'Serverless' },
  { name: 'Firecracker', icon: '🔥', category: 'Runtimes' },
  { name: 'Corretto', icon: '☕', category: 'Runtimes' },
  { name: 'OpenSearch', icon: '🔍', category: 'Data' },
  { name: 'Cedar', icon: '🛡️', category: 'Policy' },
];

export const TRACKER_COLORS = {
  analytics: '#3b82f6',
  advertising: '#ef4444',
  session_recording: '#f59e0b',
  marketing: '#8b5cf6',
  monitoring: '#6366f1',
  infrastructure: '#10b981',
  unknown: '#94a3b8',
};

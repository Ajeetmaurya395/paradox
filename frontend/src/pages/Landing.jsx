import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../utils/api'
import { AWS_TOOLS, MODE_CONFIG } from '../utils/constants'
import './Landing.css'

export default function Landing() {
  const [url, setUrl] = useState('')
  const [modes, setModes] = useState(['security', 'privacy'])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const toggleMode = (mode) => {
    setModes(prev =>
      prev.includes(mode) ? prev.filter(m => m !== mode) : [...prev, mode]
    )
  }

  const handleScan = async () => {
    if (!url.trim()) { setError('Please enter a URL'); return }
    if (modes.length === 0) { setError('Select at least one scan mode'); return }

    let targetUrl = url.trim()
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl

    setLoading(true)
    setError('')

    try {
      const result = await api.startScan(targetUrl, modes)
      navigate(`/scan/${result.scan_id}`)
    } catch (e) {
      setError('Failed to start scan. Is the backend running?')
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => { if (e.key === 'Enter') handleScan() }

  return (
    <div className="landing">
      {/* Floating particles */}
      {[...Array(12)].map((_, i) => (
        <div
          key={i}
          className="particle"
          style={{
            left: `${Math.random() * 100}%`,
            width: `${2 + Math.random() * 4}px`,
            height: `${2 + Math.random() * 4}px`,
            background: i % 3 === 0 ? 'var(--accent-cyan)' : i % 3 === 1 ? 'var(--accent-purple)' : 'var(--accent-amber)',
            animationDuration: `${10 + Math.random() * 20}s`,
            animationDelay: `${Math.random() * 10}s`,
          }}
        />
      ))}

      <div className="landing-content">
        {/* Hero */}
        <div className="hero-section">
          <div className="hero-badge">AI-Powered Security Platform</div>
          <h1 className="hero-title">
            <span className="hero-gradient">Paradox</span>
          </h1>
          <p className="hero-subtitle">
            See what hackers see, before they do.
          </p>
          <p className="hero-description">
            Stress-test websites and AI agents with security scans, privacy leak detection,
            and adversarial red-team attacks — all powered by AI.
          </p>
        </div>

        {/* Scan Input */}
        <div className="scan-input-section glass-card">
          <div className="input-wrapper">
            <span className="input-icon">🎯</span>
            <input
              type="text"
              className="scan-url-input"
              placeholder="Enter website URL or agent endpoint..."
              value={url}
              onChange={(e) => { setUrl(e.target.value); setError('') }}
              onKeyDown={handleKeyDown}
              autoFocus
            />
          </div>

          {/* Mode Toggles */}
          <div className="mode-toggles">
            {Object.entries(MODE_CONFIG).map(([key, config]) => (
              <button
                key={key}
                className={`mode-pill ${modes.includes(key) ? 'active' : ''} ${config.bgClass}`}
                onClick={() => toggleMode(key)}
              >
                <span>{config.icon}</span>
                <span>{config.label}</span>
                {modes.includes(key) && <span className="pill-check">✓</span>}
              </button>
            ))}
          </div>

          {error && <div className="scan-error">{error}</div>}

          <button
            className={`scan-button btn-primary ${loading ? 'loading' : ''}`}
            onClick={handleScan}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner" />
                Initializing Scan...
              </>
            ) : (
              <>
                <span>⚡</span>
                Launch Scan
              </>
            )}
          </button>
        </div>

        {/* Quick targets */}
        <div className="quick-targets">
          <span className="quick-label">Try:</span>
          {[
            { label: 'Test Vulns', url: 'http://testphp.vulnweb.com' },
            { label: 'Demo Agent', url: 'http://localhost:8000/api/agent/chat' },
          ].map((target) => (
            <button
              key={target.url}
              className="quick-target-btn"
              onClick={() => setUrl(target.url)}
            >
              {target.label}
            </button>
          ))}
        </div>

        {/* AWS Tools Showcase */}
        <div className="tools-showcase">
          <h3 className="tools-title">⚡ Powered by AWS Open Source</h3>
          <div className="tools-grid">
            {AWS_TOOLS.map((tool) => (
              <div key={tool.name} className="tool-badge glass-card">
                <span className="tool-icon">{tool.icon}</span>
                <span className="tool-name">{tool.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

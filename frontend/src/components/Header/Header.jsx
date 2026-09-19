import { Link, useLocation } from 'react-router-dom'
import './Header.css'

export default function Header() {
  const location = useLocation()

  return (
    <header className="header">
      <div className="header-inner">
        <Link to="/" className="header-logo">
          <div className="logo-icon">◈</div>
          <span className="logo-text">PARADOX</span>
          <span className="logo-tag">AI Security</span>
        </Link>

        <nav className="header-nav">
          <Link to="/" className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}>
            <span className="nav-icon">⚡</span> Scan
          </Link>
          <Link to="/history" className={`nav-link ${location.pathname === '/history' ? 'active' : ''}`}>
            <span className="nav-icon">📋</span> History
          </Link>
        </nav>

        <div className="header-status">
          <div className="status-dot pulse-dot success" />
          <span className="status-text">Ollama Online</span>
        </div>
      </div>
    </header>
  )
}

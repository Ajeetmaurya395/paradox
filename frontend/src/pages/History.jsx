import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../utils/api'
import { MODE_CONFIG } from '../utils/constants'
import './History.css'

export default function History() {
  const [scans, setScans] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchData() {
      try {
        const [scansData, statsData] = await Promise.all([
          api.getScans(),
          api.getStats()
        ])
        setScans(scansData.scans || [])
        setStats(statsData)
      } catch (err) {
        setError('Failed to load history.')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const handleDelete = async (scanId) => {
    if (!window.confirm('Delete this scan?')) return
    try {
      await api.deleteScan(scanId)
      setScans(prev => prev.filter(s => s.id !== scanId))
      setStats(await api.getStats())
    } catch (e) {
      alert('Failed to delete scan.')
    }
  }

  if (loading) return <div className="history-loading"><div className="spinner"/> Loading history...</div>
  if (error) return <div className="history-error">{error}</div>

  return (
    <div className="history-page">
      <div className="history-header">
        <h1 className="history-title">Scan History</h1>
      </div>

      {stats && (
        <div className="stats-cards">
          <div className="glass-card stat-card">
            <span className="stat-label">Total Scans</span>
            <span className="stat-value">{stats.total_scans}</span>
          </div>
          <div className="glass-card stat-card">
            <span className="stat-label">Avg Security Score</span>
            <span className="stat-value text-cyan">{stats.avg_security_score}</span>
          </div>
          <div className="glass-card stat-card">
            <span className="stat-label">Avg Privacy Score</span>
            <span className="stat-value text-purple">{stats.avg_privacy_score}</span>
          </div>
          <div className="glass-card stat-card">
            <span className="stat-label">Avg Agent Score</span>
            <span className="stat-value text-amber">{stats.avg_agent_score}</span>
          </div>
        </div>
      )}

      <div className="scans-list">
        {scans.length === 0 ? (
          <div className="glass-card history-empty">
            <p>No scans found.</p>
            <Link to="/" className="btn btn-primary">Start a Scan</Link>
          </div>
        ) : (
          scans.map(scan => (
            <div key={scan.id} className="glass-card scan-list-item">
              <div className="scan-item-main">
                <Link to={`/results/${scan.id}`} className="scan-item-target">{scan.target_url}</Link>
                <div className="scan-item-meta">
                  <span>{new Date(scan.started_at).toLocaleString()}</span>
                  <span>•</span>
                  <span>{scan.total_findings || 0} findings</span>
                </div>
                <div className="scan-item-modes">
                  {scan.scan_modes?.map(m => (
                    <span key={m} className={`badge ${MODE_CONFIG[m]?.bgClass}`}>
                      {MODE_CONFIG[m]?.icon} {MODE_CONFIG[m]?.label}
                    </span>
                  ))}
                </div>
              </div>
              
              <div className="scan-item-score">
                <span className="score-label">Overall</span>
                <span className={`score-value ${scan.overall_score >= 80 ? 'text-success' : scan.overall_score >= 50 ? 'text-warning' : 'text-danger'}`}>
                  {scan.overall_score || 0}
                </span>
              </div>
              
              <div className="scan-item-actions">
                <Link to={`/results/${scan.id}`} className="btn btn-secondary">View</Link>
                <button onClick={() => handleDelete(scan.id)} className="btn btn-danger">🗑️</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

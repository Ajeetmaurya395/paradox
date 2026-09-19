import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../utils/api'
import ScoreGauge from '../components/ScoreGauge/ScoreGauge'
import FindingsList from '../components/FindingsList/FindingsList'
import FindingDetail from '../components/FindingDetail/FindingDetail'
import NetworkGraph from '../components/NetworkGraph/NetworkGraph'
import BattleArena from '../components/BattleArena/BattleArena'
import { MODE_CONFIG } from '../utils/constants'
import './Results.css'

export default function Results() {
  const { scanId } = useParams()
  const [scan, setScan] = useState(null)
  const [compliance, setCompliance] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [activeTab, setActiveTab] = useState('summary')

  useEffect(() => {
    async function fetchData() {
      try {
        const [scanData, compData] = await Promise.all([
          api.getScan(scanId),
          api.getCompliance(scanId)
        ])
        setScan(scanData)
        setCompliance(compData)
      } catch (err) {
        setError('Failed to load scan results.')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [scanId])

  if (loading) return <div className="results-loading"><div className="spinner"/> Loading results...</div>
  if (error) return <div className="results-error">{error}</div>
  if (!scan) return <div className="results-error">Scan not found.</div>

  // Generate PartyRock URL (mocked to AWS target for demo)
  const partyRockUrl = `https://partyrock.aws/u/paradox/security-report?scan_id=${scanId}&score=${scan.overall_score || 0}`

  return (
    <div className="results-page">
      <div className="results-header glass-card">
        <div>
          <h1 className="results-title">Scan Results</h1>
          <div className="results-target">{scan.target_url}</div>
          <div className="results-meta">
            <span>Completed: {new Date(scan.completed_at || scan.started_at).toLocaleString()}</span>
            <span>ID: {scanId}</span>
          </div>
        </div>
        <div className="results-actions">
          <a href={partyRockUrl} target="_blank" rel="noreferrer" className="btn btn-primary partyrock-btn">
            🎮 Generate Executive Summary in PartyRock
          </a>
          <Link to="/" className="btn btn-secondary">New Scan</Link>
        </div>
      </div>

      <div className="results-content">
        <div className="results-sidebar">
          <div className="glass-card score-overview">
            <h3 className="section-title">Overall Score</h3>
            <ScoreGauge score={scan.overall_score || 0} size={160} />
            
            <div className="sub-scores">
              {scan.scan_modes?.includes('security') && (
                <div className="sub-score">
                  <span className="sub-score-label">Security</span>
                  <span className="sub-score-value text-cyan">{scan.security_score || 0}</span>
                </div>
              )}
              {scan.scan_modes?.includes('privacy') && (
                <div className="sub-score">
                  <span className="sub-score-label">Privacy</span>
                  <span className="sub-score-value text-purple">{scan.privacy_score || 0}</span>
                </div>
              )}
              {scan.scan_modes?.includes('agent') && (
                <div className="sub-score">
                  <span className="sub-score-label">Agent</span>
                  <span className="sub-score-value text-amber">{scan.agent_score || 0}</span>
                </div>
              )}
            </div>
          </div>

          <div className="glass-card findings-summary">
            <h3 className="section-title">Findings Summary</h3>
            <div className="severity-bar-chart">
              {Object.entries(scan.findings_by_severity || {}).map(([sev, count]) => {
                if (count === 0) return null
                return (
                  <div key={sev} className="sev-row">
                    <span className="sev-label">{sev}</span>
                    <div className="sev-bar-container">
                      <div className={`sev-bar sev-${sev}`} style={{ width: `${(count / scan.total_findings) * 100}%` }} />
                    </div>
                    <span className="sev-count">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="glass-card compliance-summary">
            <h3 className="section-title">Cedar Compliance</h3>
            <div className="comp-circle">
              <span className="comp-value">{compliance?.compliance_rate || 100}%</span>
              <span className="comp-label">Compliant</span>
            </div>
            <p className="comp-desc">
              {compliance?.non_compliant || 0} policy violations detected
            </p>
          </div>
        </div>

        <div className="results-main glass-card">
          <div className="panel-tabs">
            <button className={`tab-btn ${activeTab === 'summary' ? 'active' : ''}`} onClick={() => setActiveTab('summary')}>
              All Findings ({scan.findings?.length || 0})
            </button>
            {scan.scan_modes?.includes('privacy') && (
              <button className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>
                Privacy Graph
              </button>
            )}
            {scan.scan_modes?.includes('agent') && (
              <button className={`tab-btn ${activeTab === 'arena' ? 'active' : ''}`} onClick={() => setActiveTab('arena')}>
                Agent Battle Log
              </button>
            )}
          </div>

          <div className="results-tab-content">
            {activeTab === 'summary' && (
              <FindingsList findings={scan.findings} onSelectFinding={setSelectedFinding} />
            )}
            
            {activeTab === 'graph' && (
              <div className="results-placeholder">
                <NetworkGraph graphData={{nodes:[], edges:[]}} targetUrl={scan.target_url} />
                <p>Note: Full graph data is only available during live scan in this demo.</p>
              </div>
            )}
            
            {activeTab === 'arena' && (
              <div className="results-placeholder">
                <BattleArena rounds={[]} />
                <p>Note: Full battle log is only available during live scan in this demo.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {selectedFinding && (
        <FindingDetail 
          finding={selectedFinding} 
          onClose={() => setSelectedFinding(null)} 
        />
      )}
    </div>
  )
}

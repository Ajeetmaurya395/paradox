import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { createScanSocket } from '../utils/websocket'
import ScoreGauge from '../components/ScoreGauge/ScoreGauge'
import AttackFeed from '../components/AttackFeed/AttackFeed'
import NetworkGraph from '../components/NetworkGraph/NetworkGraph'
import BattleArena from '../components/BattleArena/BattleArena'
import FindingsList from '../components/FindingsList/FindingsList'
import FindingDetail from '../components/FindingDetail/FindingDetail'
import { MODE_CONFIG } from '../utils/constants'
import './ScanDashboard.css'

export default function ScanDashboard() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  
  const [events, setEvents] = useState([])
  const [findings, setFindings] = useState([])
  const [scanState, setScanState] = useState('initializing')
  const [modes, setModes] = useState([])
  const [target, setTarget] = useState('')
  const [activeTab, setActiveTab] = useState('feed')
  
  // Data for visualizers
  const [graphData, setGraphData] = useState(null)
  const [battleRounds, setBattleRounds] = useState([])
  const [scores, setScores] = useState({ overall: 0, security: 0, privacy: 0, agent: 0 })
  
  const [selectedFinding, setSelectedFinding] = useState(null)

  useEffect(() => {
    const ws = createScanSocket(scanId, {
      onScanStarted: (data) => {
        setScanState('running')
        setTarget(data.data.target)
        setModes(data.data.modes || [])
      },
      onFinding: (data) => {
        setFindings(prev => [...prev, data.data])
      },
      onGraphData: (data) => {
        setGraphData(data.data)
      },
      onAttackResult: (data) => {
        setBattleRounds(prev => [...prev, data.data.round])
      },
      onModeCompleted: (data) => {
        setScores(prev => ({ ...prev, [data.mode]: data.data.score }))
      },
      onScanComplete: (data) => {
        setScanState('completed')
        setScores(prev => ({ ...prev, overall: data.data.overall_score }))
        setTimeout(() => navigate(`/results/${scanId}`), 3000)
      },
      onEvent: (data) => {
        setEvents(prev => [...prev, data])
      },
      onError: (data) => {
        console.error('Scan error:', data)
      }
    })

    return () => ws.close()
  }, [scanId, navigate])

  const renderVisualizer = () => {
    switch (activeTab) {
      case 'feed':
        return <AttackFeed events={events} />
      case 'graph':
        return <NetworkGraph graphData={graphData || {nodes:[], edges:[]}} targetUrl={target} />
      case 'arena':
        return <BattleArena rounds={battleRounds} />
      case 'findings':
        return <FindingsList findings={findings} onSelectFinding={setSelectedFinding} />
      default:
        return null
    }
  }

  return (
    <div className="scan-dashboard">
      <div className="dashboard-header">
        <div>
          <h2 className="target-url">{target || 'Initializing...'}</h2>
          <div className="scan-status">
            <span className={`status-dot pulse-dot ${scanState === 'running' ? 'success' : ''}`} />
            Scan {scanState}
          </div>
        </div>
        
        <div className="active-modes">
          {modes.map(m => (
            <span key={m} className={`badge ${MODE_CONFIG[m]?.bgClass}`}>
              {MODE_CONFIG[m]?.icon} {MODE_CONFIG[m]?.label}
            </span>
          ))}
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="main-panel glass-card">
          <div className="panel-tabs">
            <button className={`tab-btn ${activeTab === 'feed' ? 'active' : ''}`} onClick={() => setActiveTab('feed')}>
              Live Feed
            </button>
            {modes.includes('privacy') && (
              <button className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>
                Network Graph
              </button>
            )}
            {modes.includes('agent') && (
              <button className={`tab-btn ${activeTab === 'arena' ? 'active' : ''}`} onClick={() => setActiveTab('arena')}>
                Battle Arena
              </button>
            )}
            <button className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>
              Findings ({findings.length})
            </button>
          </div>
          
          <div className="panel-content">
            {renderVisualizer()}
          </div>
        </div>

        <div className="side-panel">
          <div className="scores-grid">
            <div className="glass-card score-card">
              <h3>Overall</h3>
              <ScoreGauge score={scores.overall} size={100} />
            </div>
            {modes.includes('security') && (
              <div className="glass-card score-card">
                <h3>Security</h3>
                <ScoreGauge score={scores.security} size={80} color="var(--accent-cyan)" />
              </div>
            )}
            {modes.includes('privacy') && (
              <div className="glass-card score-card">
                <h3>Privacy</h3>
                <ScoreGauge score={scores.privacy} size={80} color="var(--accent-purple)" />
              </div>
            )}
            {modes.includes('agent') && (
              <div className="glass-card score-card">
                <h3>Agent</h3>
                <ScoreGauge score={scores.agent} size={80} color="var(--accent-amber)" />
              </div>
            )}
          </div>
          
          <div className="glass-card stats-card">
            <h3>Scan Stats</h3>
            <div className="stat-row">
              <span>Events</span>
              <span className="text-mono">{events.length}</span>
            </div>
            <div className="stat-row">
              <span>Vulnerabilities</span>
              <span className="text-mono text-danger">{findings.filter(f => f.severity === 'critical' || f.severity === 'high').length}</span>
            </div>
            <div className="stat-row">
              <span>Warnings</span>
              <span className="text-mono text-warning">{findings.filter(f => f.severity === 'medium').length}</span>
            </div>
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

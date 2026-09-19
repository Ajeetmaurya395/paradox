import { SEVERITY_CONFIG, MODE_CONFIG } from '../../utils/constants'
import './FindingsList.css'

export default function FindingsList({ findings = [], onSelectFinding }) {
  if (findings.length === 0) {
    return (
      <div className="findings-empty glass-card">
        <span className="empty-icon">🛡️</span>
        <p>No vulnerabilities or issues found yet.</p>
      </div>
    )
  }

  return (
    <div className="findings-list">
      {findings.map((finding) => (
        <div 
          key={finding.id} 
          className="finding-item glass-card"
          onClick={() => onSelectFinding(finding)}
        >
          <div className="finding-header">
            <span className={`badge ${SEVERITY_CONFIG[finding.severity]?.bgClass || 'badge-info'}`}>
              {finding.severity}
            </span>
            <span className={`mode-indicator ${MODE_CONFIG[finding.mode]?.textClass}`}>
              {MODE_CONFIG[finding.mode]?.icon} {MODE_CONFIG[finding.mode]?.label}
            </span>
          </div>
          <h4 className="finding-title">{finding.title}</h4>
          <p className="finding-desc">{finding.description}</p>
        </div>
      ))}
    </div>
  )
}

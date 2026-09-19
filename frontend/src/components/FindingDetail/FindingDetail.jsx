import { SEVERITY_CONFIG } from '../../utils/constants'
import './FindingDetail.css'

export default function FindingDetail({ finding, onClose }) {
  if (!finding) return null

  return (
    <div className="finding-detail-overlay">
      <div className="finding-detail glass-card">
        <button className="detail-close" onClick={onClose}>✕</button>
        
        <div className="detail-header">
          <span className={`badge ${SEVERITY_CONFIG[finding.severity]?.bgClass || 'badge-info'}`}>
            {finding.severity} Severity
          </span>
          {finding.cedar_policy && (
            <span className="badge badge-info">🛡️ {finding.cedar_policy}</span>
          )}
        </div>

        <h2 className="detail-title">{finding.title}</h2>
        
        <div className="detail-section">
          <h3>Description</h3>
          <p>{finding.description}</p>
        </div>

        {finding.evidence && Object.keys(finding.evidence).length > 0 && (
          <div className="detail-section">
            <h3>Evidence</h3>
            <pre className="evidence-block">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        )}

        {finding.fix_suggestion && (
          <div className="detail-section">
            <h3>Remediation</h3>
            <div className="fix-suggestion" dangerouslySetInnerHTML={{ __html: formatMarkdown(finding.fix_suggestion) }} />
          </div>
        )}
      </div>
    </div>
  )
}

function formatMarkdown(text) {
  if (!text) return ''
  let html = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/```(.*?)```/gs, '<pre><code>$1</code></pre>')
  html = html.replace(/`(.*?)`/g, '<code>$1</code>')
  html = html.replace(/\n/g, '<br/>')
  return html
}

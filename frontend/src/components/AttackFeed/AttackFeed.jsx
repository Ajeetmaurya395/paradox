import { useEffect, useRef } from 'react'
import { MODE_CONFIG } from '../../utils/constants'
import './AttackFeed.css'

export default function AttackFeed({ events = [] }) {
  const feedRef = useRef(null)

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight
    }
  }, [events])

  const getEventIcon = (event) => {
    switch (event.event_type) {
      case 'scan_started': return '🚀'
      case 'mode_started': return '▶️'
      case 'attack_started': return '⚡'
      case 'check_passed': return '✅'
      case 'finding': return '🔴'
      case 'tracker_found': return '📡'
      case 'attack_sent': return '⚔️'
      case 'attack_result': return event.data?.result === 'DEFENDED' ? '🛡️' : '💥'
      case 'mode_completed': return '🏁'
      case 'scan_complete': return '🎯'
      case 'error': return '⚠️'
      default: return '•'
    }
  }

  const getModeClass = (mode) => {
    if (mode === 'security') return 'event-security'
    if (mode === 'privacy') return 'event-privacy'
    if (mode === 'agent') return 'event-agent'
    return ''
  }

  return (
    <div className="attack-feed glass-card">
      <div className="feed-header">
        <div className="feed-title">
          <div className="pulse-dot" />
          <span>Live Attack Feed</span>
        </div>
        <span className="feed-count">{events.length} events</span>
      </div>
      <div className="feed-events" ref={feedRef}>
        {events.length === 0 ? (
          <div className="feed-empty">Waiting for scan events...</div>
        ) : (
          events.map((event, i) => (
            <div key={i} className={`feed-event ${getModeClass(event.mode)}`}
                 style={{ animationDelay: `${i * 0.05}s` }}>
              <span className="event-icon">{getEventIcon(event)}</span>
              <div className="event-content">
                <span className="event-message">{event.message}</span>
                <span className="event-time">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
              </div>
              {event.event_type === 'finding' && (
                <span className="badge badge-danger">VULN</span>
              )}
              {event.event_type === 'check_passed' && (
                <span className="badge badge-success">PASS</span>
              )}
              {event.event_type === 'attack_result' && (
                <span className={`badge ${event.data?.result === 'DEFENDED' ? 'badge-success' : 'badge-danger'}`}>
                  {event.data?.result || 'RESULT'}
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

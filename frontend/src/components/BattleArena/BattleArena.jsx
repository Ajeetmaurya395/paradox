import { useEffect, useRef } from 'react'
import './BattleArena.css'

export default function BattleArena({ rounds = [] }) {
  const arenaRef = useRef(null)
  const lastRound = rounds[rounds.length - 1]

  useEffect(() => {
    if (arenaRef.current) {
      arenaRef.current.scrollTop = arenaRef.current.scrollHeight
    }
  }, [rounds])

  const attackerScore = rounds.filter(r => r.result === 'COMPROMISED').length
  const defenderScore = rounds.filter(r => r.result === 'DEFENDED').length

  return (
    <div className="battle-arena glass-card">
      <div className="arena-header">
        <span className="arena-title">⚔️ Battle Arena</span>
        <div className="arena-scores">
          <span className="score-attacker">🔴 {attackerScore}</span>
          <span className="score-separator">vs</span>
          <span className="score-defender">🔵 {defenderScore}</span>
        </div>
      </div>

      <div className="arena-content" ref={arenaRef}>
        {rounds.length === 0 ? (
          <div className="arena-empty">
            <div className="arena-waiting">⚔️</div>
            <p>Waiting for battle to begin...</p>
          </div>
        ) : (
          rounds.map((round, i) => (
            <div key={i} className="battle-round" style={{ animationDelay: `${i * 0.1}s` }}>
              <div className="round-header">
                <span className="round-number">Round {round.round}</span>
                <span className="round-category">{round.category_name}</span>
                <span className={`badge ${round.result === 'DEFENDED' ? 'badge-success' : round.result === 'COMPROMISED' ? 'badge-danger' : 'badge-medium'}`}>
                  {round.result}
                </span>
              </div>

              <div className="round-battle">
                {/* Attacker side */}
                <div className="battle-side attacker-side">
                  <div className="side-label">🔴 Attacker</div>
                  <div className="side-message">
                    {round.attack_prompt?.substring(0, 120)}
                    {round.attack_prompt?.length > 120 ? '...' : ''}
                  </div>
                </div>

                <div className="battle-vs">VS</div>

                {/* Defender side */}
                <div className="battle-side defender-side">
                  <div className="side-label">🔵 Defender</div>
                  <div className="side-message">
                    {round.defender_response?.substring(0, 120)}
                    {round.defender_response?.length > 120 ? '...' : ''}
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Score bar */}
      <div className="arena-score-bar">
        <div className="score-bar-fill attacker-fill"
          style={{ width: rounds.length > 0 ? `${(attackerScore / rounds.length) * 100}%` : '50%' }} />
        <div className="score-bar-fill defender-fill"
          style={{ width: rounds.length > 0 ? `${(defenderScore / rounds.length) * 100}%` : '50%' }} />
      </div>
    </div>
  )
}

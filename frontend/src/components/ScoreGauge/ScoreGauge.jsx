import { useEffect, useState } from 'react'
import './ScoreGauge.css'

export default function ScoreGauge({ score = 0, label = 'Score', size = 120, color, animate = true }) {
  const [currentScore, setCurrentScore] = useState(0)
  const radius = (size - 12) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (currentScore / 100) * circumference

  const getColor = () => {
    if (color) return color
    if (currentScore >= 80) return 'var(--success)'
    if (currentScore >= 50) return 'var(--warning)'
    return 'var(--danger)'
  }

  useEffect(() => {
    if (!animate) { setCurrentScore(score); return }
    let frame
    const start = performance.now()
    const duration = 1500
    const tick = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setCurrentScore(Math.round(eased * score))
      if (progress < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [score, animate])

  return (
    <div className="score-gauge" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} className="score-ring">
        {/* Background ring */}
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="var(--border-color)" strokeWidth="6"
        />
        {/* Score ring */}
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={getColor()} strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{
            transition: 'stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s',
            filter: `drop-shadow(0 0 6px ${getColor()})`,
          }}
        />
      </svg>
      <div className="score-value">
        <span className="score-number" style={{ color: getColor() }}>{currentScore}</span>
        <span className="score-label">{label}</span>
      </div>
    </div>
  )
}

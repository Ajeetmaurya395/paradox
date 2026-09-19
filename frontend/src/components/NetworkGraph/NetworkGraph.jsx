import { useEffect, useState } from 'react'
import { TRACKER_COLORS } from '../../utils/constants'
import './NetworkGraph.css'

export default function NetworkGraph({ graphData, targetUrl }) {
  const [visibleNodes, setVisibleNodes] = useState(1)
  const [hoveredNode, setHoveredNode] = useState(null)

  const nodes = graphData?.nodes || []
  const edges = graphData?.edges || []

  // Animate nodes appearing one by one
  useEffect(() => {
    if (nodes.length <= 1) return
    const timer = setInterval(() => {
      setVisibleNodes(prev => {
        if (prev >= nodes.length) { clearInterval(timer); return prev }
        return prev + 1
      })
    }, 400)
    return () => clearInterval(timer)
  }, [nodes.length])

  const width = 600
  const height = 400
  const cx = width / 2
  const cy = height / 2

  // Position nodes in a circle around center
  const getNodePosition = (index, total) => {
    if (index === 0) return { x: cx, y: cy }
    const angle = ((index - 1) / (total - 1)) * 2 * Math.PI - Math.PI / 2
    const radius = 150
    return {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    }
  }

  return (
    <div className="network-graph glass-card">
      <div className="graph-header">
        <span className="graph-title">📡 Privacy Network Graph</span>
        <span className="graph-count">{nodes.length - 1} trackers found</span>
      </div>
      <div className="graph-container">
        <svg viewBox={`0 0 ${width} ${height}`} className="graph-svg">
          <defs>
            {Object.entries(TRACKER_COLORS).map(([cat, color]) => (
              <radialGradient key={cat} id={`glow-${cat}`}>
                <stop offset="0%" stopColor={color} stopOpacity="0.6" />
                <stop offset="100%" stopColor={color} stopOpacity="0" />
              </radialGradient>
            ))}
          </defs>

          {/* Edges */}
          {edges.map((edge, i) => {
            const sourceIdx = nodes.findIndex(n => n.id === edge.source)
            const targetIdx = nodes.findIndex(n => n.id === edge.target)
            if (sourceIdx < 0 || targetIdx < 0 || targetIdx >= visibleNodes) return null
            const s = getNodePosition(sourceIdx, nodes.length)
            const t = getNodePosition(targetIdx, nodes.length)
            const color = TRACKER_COLORS[edge.category] || '#94a3b8'
            return (
              <g key={i}>
                <line x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke={color} strokeWidth="1" strokeOpacity="0.3" />
                <line x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke={color} strokeWidth="2" strokeOpacity="0.7"
                  strokeDasharray="4 4"
                  className="edge-flow" />
              </g>
            )
          })}

          {/* Nodes */}
          {nodes.map((node, i) => {
            if (i >= visibleNodes) return null
            const pos = getNodePosition(i, nodes.length)
            const color = node.type === 'target'
              ? 'var(--accent-cyan)'
              : TRACKER_COLORS[node.category] || '#94a3b8'
            const size = node.type === 'target' ? 28 : (node.risk === 'high' ? 18 : 14)

            return (
              <g key={node.id}
                 className={`graph-node ${i > 0 ? 'node-enter' : ''}`}
                 style={{ animationDelay: `${i * 0.3}s` }}
                 onMouseEnter={() => setHoveredNode(node)}
                 onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Glow */}
                <circle cx={pos.x} cy={pos.y} r={size * 1.8}
                  fill={`url(#glow-${node.category || 'unknown'})`}
                  opacity="0.4" />
                {/* Main circle */}
                <circle cx={pos.x} cy={pos.y} r={size}
                  fill={node.type === 'target' ? 'var(--bg-primary)' : 'var(--bg-card)'}
                  stroke={color} strokeWidth="2"
                  className={node.category === 'unknown' ? 'unknown-pulse' : ''} />
                {/* Label */}
                <text x={pos.x} y={pos.y + size + 14}
                  textAnchor="middle" fill="var(--text-secondary)"
                  fontSize="9" fontFamily="var(--font-ui)">
                  {(node.label || '').substring(0, 16)}
                </text>
                {/* Icon for target */}
                {node.type === 'target' && (
                  <text x={pos.x} y={pos.y + 5} textAnchor="middle"
                    fontSize="16" fill={color}>🎯</text>
                )}
              </g>
            )
          })}
        </svg>

        {/* Tooltip */}
        {hoveredNode && hoveredNode.type !== 'target' && (
          <div className="graph-tooltip glass-card">
            <div className="tooltip-name">{hoveredNode.label}</div>
            <div className="tooltip-company">{hoveredNode.company}</div>
            <div className="tooltip-category">
              <span className="tooltip-dot" style={{ background: TRACKER_COLORS[hoveredNode.category] }} />
              {hoveredNode.category}
            </div>
            <div className="tooltip-data">{hoveredNode.data_collected}</div>
            <div className={`badge badge-${hoveredNode.risk === 'high' ? 'danger' : hoveredNode.risk === 'medium' ? 'medium' : 'info'}`}>
              {hoveredNode.risk} risk
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="graph-legend">
        {Object.entries(TRACKER_COLORS).filter(([k]) => k !== 'unknown').map(([cat, color]) => (
          <div key={cat} className="legend-item">
            <span className="legend-dot" style={{ background: color }} />
            <span>{cat}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

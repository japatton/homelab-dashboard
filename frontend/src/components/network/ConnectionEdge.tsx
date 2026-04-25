import { memo } from 'react'
import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from 'reactflow'
import type { EdgeData } from '../../types/topology'

interface ConnectionEdgeProps extends EdgeProps {
  data?: EdgeData
}

function ConnectionEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: ConnectionEdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const isWireless = data?.connection_type === 'wireless'
  const isActive = data?.is_active ?? true

  const strokeColor = selected
    ? '#00e5ff'
    : isActive
    ? isWireless ? '#0ea5e9' : 'rgba(0,229,255,0.6)'
    : 'rgba(107,114,128,0.3)'

  const strokeWidth = selected ? 2.5 : isActive ? 1.5 : 1
  const strokeDasharray = isWireless ? '6 3' : undefined

  // Perf: drop-shadow + infinite CSS animation are the expensive bits on
  // SVG edges. Apply shadow only when selected, and only animate wireless
  // links (wired links far outnumber wireless in a typical homelab).
  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: strokeColor,
          strokeWidth,
          strokeDasharray,
          animation: isWireless && isActive ? 'dataFlow 1.5s linear infinite' : undefined,
          filter: selected ? `drop-shadow(0 0 3px ${strokeColor})` : undefined,
        }}
      />

      {data?.bandwidth_mbps !== undefined && selected && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: 'none',
            }}
            className="px-1.5 py-0.5 bg-tron-panel border border-tron-border rounded text-tron-cyan font-mono text-xs"
          >
            {data.bandwidth_mbps >= 1000
              ? `${(data.bandwidth_mbps / 1000).toFixed(0)}G`
              : `${data.bandwidth_mbps}M`}
            {isWireless && data.signal_strength && ` ${data.signal_strength}dBm`}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

export const ConnectionEdge = memo(ConnectionEdgeComponent)

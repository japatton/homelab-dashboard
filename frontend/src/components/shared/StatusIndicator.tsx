import type { DeviceStatus } from '../../types/device'

interface StatusIndicatorProps {
  status: DeviceStatus | string
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
}

const statusConfig: Record<string, { color: string; glow: string; label: string }> = {
  online:   { color: 'bg-status-online',  glow: 'shadow-status-online',  label: 'Online' },
  offline:  { color: 'bg-status-offline', glow: 'shadow-status-offline', label: 'Offline' },
  scanning: { color: 'bg-status-scanning', glow: 'shadow-status-scanning', label: 'Scanning' },
  unknown:  { color: 'bg-status-unknown', glow: '', label: 'Unknown' },
}

const sizeMap = { sm: 'w-2 h-2', md: 'w-2.5 h-2.5', lg: 'w-3 h-3' }

export function StatusIndicator({ status, size = 'md', showLabel = false }: StatusIndicatorProps) {
  const cfg = statusConfig[status] ?? statusConfig.unknown
  const isAnimated = status === 'online' || status === 'scanning'

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`relative inline-flex ${sizeMap[size]}`}>
        {isAnimated && (
          <span className={`absolute inline-flex h-full w-full rounded-full ${cfg.color} opacity-75 animate-ping`} />
        )}
        <span className={`relative inline-flex rounded-full ${sizeMap[size]} ${cfg.color} ${cfg.glow}`} />
      </span>
      {showLabel && (
        <span className="text-xs font-mono" style={{ color: cfg.color.replace('bg-', '') }}>
          {cfg.label}
        </span>
      )}
    </span>
  )
}

import { ExternalLink } from 'lucide-react'
import type { DeviceService } from '../../types/device'

const serviceColors: Record<string, string> = {
  http:     'text-tron-blue  border-tron-blue/30  bg-tron-blue/10',
  https:    'text-tron-cyan  border-tron-cyan/30  bg-tron-cyan/10',
  ssh:      'text-green-400  border-green-400/30  bg-green-400/10',
  rtsp:     'text-purple-400 border-purple-400/30 bg-purple-400/10',
  smb:      'text-orange-400 border-orange-400/30 bg-orange-400/10',
  docker:   'text-blue-400   border-blue-400/30   bg-blue-400/10',
  portainer:'text-teal-400   border-teal-400/30   bg-teal-400/10',
}

const defaultColor = 'text-slate-400 border-slate-600/30 bg-slate-600/10'

interface ServiceTagProps {
  service: DeviceService
  compact?: boolean
}

export function ServiceTag({ service, compact = false }: ServiceTagProps) {
  const colorClass = serviceColors[service.name.toLowerCase()] ?? defaultColor
  const label = compact ? service.name : `${service.port}/${service.name}`

  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border font-mono text-xs ${colorClass}`}>
      {label}
      {service.launch_url && (
        <a
          href={service.launch_url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="opacity-70 hover:opacity-100 transition-opacity"
        >
          <ExternalLink size={9} />
        </a>
      )}
    </span>
  )
}

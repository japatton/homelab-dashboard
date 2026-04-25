import type { DeviceStatus, DeviceType } from '../../types/device'

const statusStyles: Record<string, string> = {
  online:   'text-status-online  bg-status-online/10  border-status-online/30',
  offline:  'text-status-offline bg-status-offline/10 border-status-offline/30',
  scanning: 'text-status-scanning bg-status-scanning/10 border-status-scanning/30',
  unknown:  'text-slate-400 bg-slate-400/10 border-slate-600/30',
}

const typeStyles: Record<string, string> = {
  gateway:     'text-tron-cyan   bg-tron-cyan/10   border-tron-cyan/30',
  switch:      'text-tron-blue   bg-tron-blue/10   border-tron-blue/30',
  ap:          'text-sky-400     bg-sky-400/10     border-sky-400/30',
  server:      'text-violet-400  bg-violet-400/10  border-violet-400/30',
  workstation: 'text-indigo-400  bg-indigo-400/10  border-indigo-400/30',
  laptop:      'text-indigo-400  bg-indigo-400/10  border-indigo-400/30',
  camera:      'text-amber-400   bg-amber-400/10   border-amber-400/30',
  doorbell:    'text-amber-400   bg-amber-400/10   border-amber-400/30',
  iot:         'text-emerald-400 bg-emerald-400/10 border-emerald-400/30',
  phone:       'text-pink-400    bg-pink-400/10    border-pink-400/30',
  unknown:     'text-slate-400   bg-slate-400/10   border-slate-600/30',
}

interface DeviceStatusBadgeProps {
  status?: DeviceStatus | string
  deviceType?: DeviceType | string
}

export function DeviceStatusBadge({ status, deviceType }: DeviceStatusBadgeProps) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {status && (
        <span className={`px-1.5 py-0.5 rounded border font-mono text-xs ${statusStyles[status] ?? statusStyles.unknown}`}>
          {status}
        </span>
      )}
      {deviceType && (
        <span className={`px-1.5 py-0.5 rounded border font-mono text-xs ${typeStyles[deviceType] ?? typeStyles.unknown}`}>
          {deviceType}
        </span>
      )}
    </span>
  )
}

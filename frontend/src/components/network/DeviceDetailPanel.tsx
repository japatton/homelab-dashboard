import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Shield, Cpu, Wifi, Clock, Tag, ChevronDown, ChevronRight, ExternalLink, Zap } from 'lucide-react'
import { useDevice } from '../../hooks/useDevices'
import { useDeviceVulns } from '../../hooks/useVulns'
import { StatusIndicator } from '../shared/StatusIndicator'
import { LoadingGrid } from '../shared/LoadingGrid'
import { ServiceTag } from '../devices/ServiceTag'
import { DeviceStatusBadge } from '../devices/DeviceStatusBadge'
import { GlowButton } from '../shared/GlowButton'
import client from '../../api/client'
import type { VulnResult, Severity } from '../../types/vulnerability'

interface DeviceDetailPanelProps {
  deviceId: string | null
  onClose: () => void
}

const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  log:      '#64748b',
  unknown:  '#64748b',
}

function VulnItem({ vuln }: { vuln: VulnResult }) {
  const [open, setOpen] = useState(false)
  const color = SEV_COLOR[vuln.severity as Severity] ?? SEV_COLOR.unknown
  const cveIds: string[] = (() => {
    try {
      const parsed = JSON.parse(vuln.cve_ids ?? '[]') as unknown
      return Array.isArray(parsed) ? parsed.map(String) : []
    }
    catch { return vuln.cve ? [vuln.cve.cve_id] : [] }
  })()

  return (
    <div className="border border-tron-border/30 rounded overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-tron-border/10 transition-colors text-left"
        onClick={() => setOpen((o) => !o)}
      >
        {open
          ? <ChevronDown size={10} className="text-tron-cyan flex-shrink-0" />
          : <ChevronRight size={10} className="text-slate-600 flex-shrink-0" />}
        <span className="font-mono font-bold text-xs flex-shrink-0 w-8" style={{ color }}>
          {vuln.score.toFixed(1)}
        </span>
        <span className="text-xs font-mono text-slate-300 truncate flex-1">{vuln.name}</span>
        {vuln.port && (
          <span className="text-xs font-mono text-slate-600 flex-shrink-0">{vuln.port}</span>
        )}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="overflow-hidden"
          >
            <div className="px-3 py-2 bg-tron-dark border-t border-tron-border/30 space-y-2">
              {cveIds.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {cveIds.map((id) => (
                    <a
                      key={id}
                      href={`https://nvd.nist.gov/vuln/detail/${id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-xs font-mono
                                 border border-tron-cyan/30 text-tron-cyan rounded
                                 hover:border-tron-cyan transition-colors"
                    >
                      {id} <ExternalLink size={8} />
                    </a>
                  ))}
                </div>
              )}
              {vuln.description && (
                <p className="text-xs font-mono text-slate-400 leading-relaxed line-clamp-4">
                  {vuln.description}
                </p>
              )}
              {vuln.solution && (
                <div>
                  <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-0.5">Fix</p>
                  <p className="text-xs font-mono text-slate-300 leading-relaxed line-clamp-3">
                    {vuln.solution}
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function DeviceDetailPanel({ deviceId, onClose }: DeviceDetailPanelProps) {
  const { data: device, isLoading } = useDevice(deviceId)
  const { data: vulnList = [] } = useDeviceVulns(deviceId)
  const [scanning, setScanning] = useState(false)

  const vulnTotal = device
    ? device.vuln_summary.critical + device.vuln_summary.high +
      device.vuln_summary.medium + device.vuln_summary.low
    : 0

  async function handleScanDevice() {
    if (!deviceId) return
    setScanning(true)
    try { await client.post(`/vulns/scan/${deviceId}`) } finally {
      setTimeout(() => setScanning(false), 1500)
    }
  }

  return (
    <AnimatePresence>
      {deviceId && (
        <motion.div
          key="detail-panel"
          initial={{ x: '100%', opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: '100%', opacity: 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="absolute right-4 top-4 bottom-4 w-80 bg-tron-panel border border-tron-border rounded-lg overflow-hidden flex flex-col z-50"
          style={{ boxShadow: '0 0 32px rgba(0,229,255,0.15)' }}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-3 border-b border-tron-border">
            <div className="flex items-center gap-2">
              {device && <StatusIndicator status={device.status} size="sm" />}
              <span className="text-tron-cyan font-mono text-sm font-medium truncate">
                {device?.label ?? device?.hostname ?? device?.ip ?? '...'}
              </span>
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-tron-cyan transition-colors">
              <X size={16} />
            </button>
          </div>

          {isLoading ? (
            <div className="p-4"><LoadingGrid rows={3} /></div>
          ) : device ? (
            <div className="flex-1 overflow-y-auto">

              {/* Identity */}
              <div className="p-3 border-b border-tron-border/50">
                <div className="mb-2">
                  <DeviceStatusBadge status={device.status} deviceType={device.device_type} />
                </div>
                <div className="space-y-1.5">
                  {[
                    { icon: Cpu,   label: 'IP',       value: device.ip },
                    { icon: Wifi,  label: 'MAC',      value: device.mac },
                    { icon: Tag,   label: 'Hostname', value: device.hostname },
                    { icon: Clock, label: 'Last seen', value: device.last_seen
                      ? new Date(device.last_seen).toLocaleTimeString()
                      : 'Unknown'
                    },
                  ].map(({ icon: Icon, label, value }) => value && (
                    <div key={label} className="flex items-center gap-2 text-xs">
                      <Icon size={11} className="text-tron-cyan flex-shrink-0" />
                      <span className="text-slate-500 w-16">{label}</span>
                      <span className="text-slate-200 font-mono truncate">{value as string}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Services */}
              {device.services.length > 0 && (
                <div className="p-3 border-b border-tron-border/50">
                  <div className="text-xs text-slate-500 font-mono uppercase tracking-wider mb-2">
                    Services ({device.services.length})
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {device.services.map((s) => (
                      <ServiceTag key={`${s.port}-${s.protocol}`} service={s} />
                    ))}
                  </div>
                </div>
              )}

              {/* Vulnerability section */}
              <div className="p-3 border-b border-tron-border/50">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs text-slate-500 font-mono uppercase tracking-wider flex items-center gap-1">
                    <Shield size={11} /> Vulnerabilities
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">{vulnTotal} total</span>
                    <GlowButton
                      size="sm"
                      variant="ghost"
                      loading={scanning}
                      onClick={handleScanDevice}
                      className="!px-2 !py-0.5 !text-xs"
                    >
                      <Zap size={10} className="mr-0.5" />
                      Scan
                    </GlowButton>
                  </div>
                </div>

                {/* Summary bars */}
                <div className="flex gap-1.5 mb-3">
                  {[
                    { label: 'C', count: device.vuln_summary.critical, color: '#ef4444' },
                    { label: 'H', count: device.vuln_summary.high,     color: '#f97316' },
                    { label: 'M', count: device.vuln_summary.medium,   color: '#eab308' },
                    { label: 'L', count: device.vuln_summary.low,      color: '#22c55e' },
                  ].map(({ label, count, color }) => (
                    <div key={label} className="flex-1 text-center py-1 rounded bg-tron-border/40">
                      <div className="font-mono font-bold text-sm" style={{ color }}>{count}</div>
                      <div className="text-xs text-slate-600 font-mono">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Expandable CVE list */}
                {vulnList.length > 0 && (
                  <div className="space-y-1">
                    {vulnList.map((v) => <VulnItem key={v.id} vuln={v} />)}
                  </div>
                )}
              </div>

              {/* Metadata */}
              {Object.keys(device.metadata).length > 0 && (
                <div className="p-3">
                  <div className="text-xs text-slate-500 font-mono uppercase tracking-wider mb-2">Info</div>
                  <div className="space-y-1">
                    {Object.entries(device.metadata).slice(0, 6).map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-xs">
                        <span className="text-slate-500 font-mono truncate">{k}</span>
                        <span className="text-slate-300 font-mono truncate">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </motion.div>
      )}
    </AnimatePresence>
  )
}

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, ChevronDown, ChevronRight, ExternalLink, Zap } from 'lucide-react'
import { useVulns, useVulnStats } from '../hooks/useVulns'
import { TronPanel } from '../components/shared/TronPanel'
import { GlowButton } from '../components/shared/GlowButton'
import client from '../api/client'
import type { VulnResult, Severity } from '../types/vulnerability'

// ── Severity config ───────────────────────────────────────────────────────────

const SEV: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Critical' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.1)', label: 'High'     },
  medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  label: 'Medium'   },
  low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  label: 'Low'      },
  log:      { color: '#64748b', bg: 'rgba(100,116,139,0.1)', label: 'Log'     },
  unknown:  { color: '#64748b', bg: 'rgba(100,116,139,0.1)', label: '?'       },
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV[severity] ?? SEV.unknown
  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-mono font-bold"
      style={{ color: s.color, background: s.bg }}
    >
      {s.label}
    </span>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-4 px-2 bg-tron-panel border border-tron-border rounded-lg">
      <span className="font-mono font-bold text-2xl" style={{ color }}>{count}</span>
      <span className="text-xs font-mono text-slate-500 mt-0.5 uppercase tracking-wide">{label}</span>
    </div>
  )
}

// ── Vuln row (expandable) ─────────────────────────────────────────────────────

function VulnRow({ vuln }: { vuln: VulnResult }) {
  const [open, setOpen] = useState(false)
  const deviceName = vuln.device_label ?? vuln.device_hostname ?? vuln.device_ip ?? vuln.device_id
  const cveIds: string[] = (() => {
    try {
      const parsed = JSON.parse(vuln.cve_ids ?? '[]') as unknown
      return Array.isArray(parsed) ? parsed.map(String) : []
    }
    catch { return vuln.cve ? [vuln.cve.cve_id] : [] }
  })()

  return (
    <>
      <tr
        className="border-b border-tron-border/30 hover:bg-tron-border/10 cursor-pointer transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <td className="py-2 px-3 w-6">
          {open ? <ChevronDown size={12} className="text-tron-cyan" /> : <ChevronRight size={12} className="text-slate-500" />}
        </td>
        <td className="py-2 px-2"><SeverityBadge severity={vuln.severity as Severity} /></td>
        <td className="py-2 px-2 font-mono text-xs" style={{ color: SEV[vuln.severity as Severity]?.color }}>
          {vuln.score.toFixed(1)}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-200 max-w-xs truncate">{vuln.name}</td>
        <td className="py-2 px-2 font-mono text-xs text-slate-400 truncate">{deviceName}</td>
        <td className="py-2 px-2 font-mono text-xs text-slate-500">
          {vuln.port ? `${vuln.port}/${vuln.protocol}` : '—'}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-600">
          {new Date(vuln.detected_at).toLocaleDateString()}
        </td>
      </tr>
      <AnimatePresence>
        {open && (
          <tr>
            <td colSpan={7} className="p-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="overflow-hidden"
              >
                <div className="px-4 py-3 bg-tron-dark border-b border-tron-border/30 space-y-3">
                  {/* CVE IDs */}
                  {cveIds.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {cveIds.map((id) => (
                        <a
                          key={id}
                          href={`https://nvd.nist.gov/vuln/detail/${id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-mono
                                     border border-tron-cyan/30 text-tron-cyan rounded
                                     hover:border-tron-cyan hover:bg-tron-cyan/5 transition-colors"
                        >
                          {id} <ExternalLink size={9} />
                        </a>
                      ))}
                    </div>
                  )}

                  {/* Description */}
                  {vuln.description && (
                    <div>
                      <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-1">Description</p>
                      <p className="text-xs font-mono text-slate-300 leading-relaxed">{vuln.description}</p>
                    </div>
                  )}

                  {/* Solution */}
                  {vuln.solution && (
                    <div>
                      <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-1">Remediation</p>
                      <p className="text-xs font-mono text-slate-300 leading-relaxed">{vuln.solution}</p>
                    </div>
                  )}
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const SEVERITY_FILTERS: Array<{ value: string; label: string }> = [
  { value: '',         label: 'All'      },
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High'     },
  { value: 'medium',   label: 'Medium'   },
  { value: 'low',      label: 'Low'      },
]

export function VulnsPage() {
  const [severityFilter, setSeverityFilter] = useState('')
  const [scanning, setScanning] = useState(false)

  const { data: stats } = useVulnStats()
  const { data: vulns = [], isLoading } = useVulns({
    severity: severityFilter || undefined,
    limit: 200,
  })

  async function handleScanAll() {
    setScanning(true)
    try {
      await client.post('/scans/openvas')
    } finally {
      setTimeout(() => setScanning(false), 2000)
    }
  }

  return (
    <div className="h-full overflow-auto p-4 space-y-4">

      {/* ── Stats row ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-3">
        <StatCard label="Total"    count={stats?.total ?? 0}            color="#00e5ff" />
        <StatCard label="Critical" count={stats?.critical ?? 0}         color="#ef4444" />
        <StatCard label="High"     count={stats?.high ?? 0}             color="#f97316" />
        <StatCard label="Medium"   count={stats?.medium ?? 0}           color="#eab308" />
        <StatCard label="Devices"  count={stats?.devices_affected ?? 0} color="#7c3aed" />
      </div>

      {/* ── Controls ───────────────────────────────────────────────── */}
      <TronPanel className="p-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {SEVERITY_FILTERS.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setSeverityFilter(value)}
              className={`px-3 py-1 text-xs font-mono border rounded transition-colors
                ${severityFilter === value
                  ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                  : 'border-tron-border text-slate-500 hover:border-tron-cyan/40 hover:text-slate-300'}`}
            >
              {label}
            </button>
          ))}
        </div>
        <GlowButton size="sm" variant="red" onClick={handleScanAll} loading={scanning}>
          <Zap size={12} className="mr-1" />
          Scan All Devices
        </GlowButton>
      </TronPanel>

      {/* ── Vuln table ─────────────────────────────────────────────── */}
      <TronPanel className="overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <Shield size={32} className="text-tron-cyan/20 mx-auto mb-2 animate-pulse" />
            <p className="text-xs font-mono text-slate-600">Loading vulnerability data…</p>
          </div>
        ) : vulns.length === 0 ? (
          <div className="p-8 text-center">
            <Shield size={32} className="text-tron-cyan/20 mx-auto mb-2" />
            <p className="text-xs font-mono text-slate-600">No vulnerabilities found</p>
            <p className="text-xs font-mono text-slate-700 mt-1">
              Trigger <span className="text-tron-cyan">OpenVAS Scan</span> from Settings → Scheduler, or
              run a per-device scan from a device panel.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-tron-border text-xs font-mono text-slate-500 uppercase tracking-wider">
                  <th className="py-2 px-3 w-6" />
                  <th className="py-2 px-2">Severity</th>
                  <th className="py-2 px-2">Score</th>
                  <th className="py-2 px-2">Finding</th>
                  <th className="py-2 px-2">Device</th>
                  <th className="py-2 px-2">Port</th>
                  <th className="py-2 px-2">Detected</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v) => <VulnRow key={v.id} vuln={v} />)}
              </tbody>
            </table>
          </div>
        )}
      </TronPanel>

    </div>
  )
}

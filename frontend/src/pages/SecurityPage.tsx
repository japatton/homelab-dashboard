import { useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert, Bell, Check, Archive,
  ChevronDown, ChevronRight, AlertOctagon, Eye, EyeOff, X,
} from 'lucide-react'

import client from '../api/client'
import { TronPanel } from '../components/shared/TronPanel'
import { GlowButton } from '../components/shared/GlowButton'
import { useSocket } from '../hooks/useSocket'

// Severity palette — intentionally mirrors VulnsPage so the visual
// vocabulary is consistent across Security and Vulnerabilities pages.
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEV_META: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  label: 'Critical' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.1)', label: 'High'     },
  medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  label: 'Medium'   },
  low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  label: 'Low'      },
  info:     { color: '#64748b', bg: 'rgba(100,116,139,0.1)', label: 'Info'    },
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

interface GatewayAlarm {
  id: string
  source: 'opnsense' | 'firewalla'
  source_label: string
  severity: Severity
  category: string
  signature: string
  message: string
  src_ip: string
  dst_ip: string
  device_id: string | null
  device_name: string
  fingerprint: string
  first_seen_at: string
  last_seen_at: string
  count: number
  acknowledged: boolean
  acknowledged_at: string | null
  dismissed: boolean
  dismissed_at: string | null
  raw: Record<string, unknown>
}

interface AlarmSummary {
  total: number
  unacknowledged: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

// ── Helpers ──────────────────────────────────────────────────────────

function fmtTs(iso: string): string {
  // "now" / "3m ago" / "2h ago" / "Apr 21" depending on distance.
  // We format relative to the user's local clock so timestamps read
  // naturally — alarms with absolute timestamps are less useful than
  // "something is actively firing" vs "something fired last night".
  if (!iso) return '—'
  const then = new Date(iso)
  const diff = Date.now() - then.getTime()
  if (diff < 60_000) return 'just now'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return then.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

function fmtAbs(iso: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

// Source chip palette — distinct colours so OPNsense vs Firewalla
// are visually separable in the feed.
const SOURCE_META: Record<string, { color: string; label: string }> = {
  opnsense:  { color: '#22c55e', label: 'OPNsense'  },
  firewalla: { color: '#e11d48', label: 'Firewalla' },
}

// ── Sub-components ───────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV_META[severity] ?? SEV_META.info
  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-mono font-bold"
      style={{ color: s.color, background: s.bg }}
    >
      {s.label}
    </span>
  )
}

function SourceChip({ source, label }: { source: string; label: string }) {
  const m = SOURCE_META[source] ?? { color: '#94a3b8', label: source }
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[10px] uppercase tracking-wider rounded border"
      style={{ color: m.color, borderColor: `${m.color}55`, background: `${m.color}11` }}
      title={label || m.label}
    >
      {m.label}
    </span>
  )
}

function StatCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-4 px-2 bg-tron-panel border border-tron-border rounded-lg">
      <span className="font-mono font-bold text-2xl" style={{ color }}>{count}</span>
      <span className="text-xs font-mono text-slate-500 mt-0.5 uppercase tracking-wide">{label}</span>
    </div>
  )
}

function AlarmRow({
  alarm,
  onAck,
  onDismiss,
}: {
  alarm: GatewayAlarm
  onAck: (id: string) => void
  onDismiss: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const sev = SEV_META[alarm.severity] ?? SEV_META.info

  return (
    <>
      <tr
        className={`border-b border-tron-border/30 hover:bg-tron-border/10 cursor-pointer transition-colors
          ${alarm.acknowledged ? 'opacity-60' : ''}`}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="py-2 px-3 w-6">
          {open
            ? <ChevronDown size={12} className="text-tron-cyan" />
            : <ChevronRight size={12} className="text-slate-500" />}
        </td>
        <td className="py-2 px-2"><SeverityBadge severity={alarm.severity} /></td>
        <td className="py-2 px-2">
          <SourceChip source={alarm.source} label={alarm.source_label} />
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-200 max-w-md truncate" title={alarm.message}>
          {alarm.message}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-400 truncate max-w-[180px]">
          {alarm.device_name || alarm.src_ip || '—'}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-500">
          {alarm.count > 1
            ? <span title={`Seen ${alarm.count} times`}>×{alarm.count}</span>
            : ''}
        </td>
        <td className="py-2 px-2 font-mono text-xs text-slate-600" title={fmtAbs(alarm.last_seen_at)}>
          {fmtTs(alarm.last_seen_at)}
        </td>
        <td className="py-2 px-2 text-right">
          <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            {!alarm.acknowledged && (
              <button
                onClick={() => onAck(alarm.id)}
                className="p-1 text-slate-500 hover:text-tron-cyan transition-colors"
                title="Acknowledge"
              >
                <Check size={12} />
              </button>
            )}
            <button
              onClick={() => onDismiss(alarm.id)}
              className="p-1 text-slate-500 hover:text-status-offline transition-colors"
              title="Dismiss"
            >
              <X size={12} />
            </button>
          </div>
        </td>
      </tr>

      <AnimatePresence>
        {open && (
          <tr>
            <td colSpan={8} className="p-0">
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="overflow-hidden"
              >
                <div className="px-4 py-3 bg-tron-dark border-b border-tron-border/30 space-y-3 text-xs font-mono">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">Signature</p>
                      <p className="text-slate-200" style={{ color: sev.color }}>{alarm.signature || alarm.category || '(unspecified)'}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">Category</p>
                      <p className="text-slate-300">{alarm.category || '—'}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">Source</p>
                      <p className="text-slate-300">{alarm.source_label || alarm.source}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">Endpoints</p>
                      <p className="text-slate-300">
                        {alarm.src_ip || '—'}
                        {alarm.dst_ip ? <span className="text-slate-600"> → </span> : ''}
                        {alarm.dst_ip || ''}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">First seen</p>
                      <p className="text-slate-400">{fmtAbs(alarm.first_seen_at)}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-slate-500 uppercase tracking-wider">Last seen</p>
                      <p className="text-slate-400">{fmtAbs(alarm.last_seen_at)}</p>
                    </div>
                    {alarm.acknowledged && (
                      <div className="space-y-1">
                        <p className="text-slate-500 uppercase tracking-wider">Acknowledged</p>
                        <p className="text-tron-cyan">{fmtAbs(alarm.acknowledged_at || '')}</p>
                      </div>
                    )}
                    {alarm.dismissed && (
                      <div className="space-y-1">
                        <p className="text-slate-500 uppercase tracking-wider">Dismissed</p>
                        <p className="text-status-offline">{fmtAbs(alarm.dismissed_at || '')}</p>
                      </div>
                    )}
                  </div>

                  {/* Raw-event drilldown — useful for power users, noisy
                      for the uninitiated, so it's collapsed into a
                      details block rather than always rendered. */}
                  {alarm.raw && Object.keys(alarm.raw).length > 0 && (
                    <details className="text-[11px]">
                      <summary className="cursor-pointer text-slate-500 uppercase tracking-wider">
                        Raw payload
                      </summary>
                      <pre className="mt-2 p-2 rounded bg-tron-panel border border-tron-border/30 text-slate-400 overflow-x-auto">
                        {JSON.stringify(alarm.raw, null, 2)}
                      </pre>
                    </details>
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

// ── Main page ────────────────────────────────────────────────────────

const SEVERITY_FILTERS: Array<{ value: string; label: string }> = [
  { value: '',         label: 'All'      },
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High'     },
  { value: 'medium',   label: 'Medium'   },
  { value: 'low',      label: 'Low'      },
  { value: 'info',     label: 'Info'     },
]

const SOURCE_FILTERS: Array<{ value: string; label: string }> = [
  { value: '',          label: 'All'       },
  { value: 'opnsense',  label: 'OPNsense'  },
  { value: 'firewalla', label: 'Firewalla' },
]

export function SecurityPage() {
  const qc = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [includeDismissed, setIncludeDismissed] = useState(false)
  const { on } = useSocket()

  const { data: summary } = useQuery<AlarmSummary>({
    queryKey: ['alarm-summary'],
    queryFn: async () => (await client.get('/alarms/summary')).data,
    refetchInterval: 60_000,
  })

  const { data, isLoading } = useQuery<{ alarms: GatewayAlarm[] }>({
    queryKey: ['alarms', { severity, source, includeDismissed }],
    queryFn: async () => (await client.get('/alarms', {
      params: {
        severity: severity || undefined,
        source: source || undefined,
        include_dismissed: includeDismissed ? 'true' : 'false',
        limit: 500,
      },
    })).data,
    // Belt-and-suspenders: the socket push below is the fast path, but
    // a 60s background refetch guarantees the feed doesn't drift if a
    // WebSocket drops or the user backgrounds the tab.
    refetchInterval: 60_000,
  })

  // Memoise the fallback so useMemo(sorted, [alarms]) below doesn't
  // see a fresh reference on every render when `data` hasn't changed.
  const alarms = useMemo(() => data?.alarms ?? [], [data?.alarms])

  // Socket.io live updates. `alarm:new` fires on genuinely-new alarms;
  // `alarm:summary` fires on ack/dismiss. We invalidate both queries
  // on either event because they're joined in the user's head — a new
  // alarm should bump the badge AND surface in the feed without a
  // manual refresh.
  useEffect(() => {
    const offNew = on('alarm:new', () => {
      qc.invalidateQueries({ queryKey: ['alarms'] })
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    })
    const offSummary = on('alarm:summary', () => {
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    })
    return () => { offNew(); offSummary() }
  }, [on, qc])

  const ack = useMutation({
    mutationFn: async (id: string) => client.post(`/alarms/${id}/acknowledge`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alarms'] })
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    },
  })

  const dismiss = useMutation({
    mutationFn: async (id: string) => client.post(`/alarms/${id}/dismiss`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alarms'] })
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    },
  })

  const clearDismissed = useMutation({
    mutationFn: async () => client.post('/alarms/clear-dismissed'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alarms'] })
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    },
  })

  // Client-side sort: unacknowledged first (so new noise surfaces),
  // then by last_seen DESC. The server already sorts by last_seen,
  // so we only invert the ack dimension here.
  const sorted = useMemo(() => {
    return [...alarms].sort((a, b) => {
      if (a.acknowledged !== b.acknowledged) return a.acknowledged ? 1 : -1
      return 0 // preserve server order for ties
    })
  }, [alarms])

  return (
    <div className="h-full overflow-auto p-4 space-y-4">

      {/* ── Severity stats row ─────────────────────────────────────── */}
      <div className="grid grid-cols-6 gap-3">
        <StatCard label="Total"          count={summary?.total ?? 0}          color="#00e5ff" />
        <StatCard label="Unacknowledged" count={summary?.unacknowledged ?? 0} color="#f59e0b" />
        {SEVERITY_ORDER.slice(0, 4).map((s) => (
          <StatCard
            key={s}
            label={SEV_META[s].label}
            count={summary?.[s] ?? 0}
            color={SEV_META[s].color}
          />
        ))}
      </div>

      {/* ── Filters & batch controls ───────────────────────────────── */}
      <TronPanel className="p-3 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-mono text-slate-500 uppercase tracking-wider">Severity</span>
          {SEVERITY_FILTERS.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setSeverity(value)}
              className={`px-3 py-1 text-xs font-mono border rounded transition-colors
                ${severity === value
                  ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                  : 'border-tron-border text-slate-500 hover:border-tron-cyan/40 hover:text-slate-300'}`}
            >
              {label}
            </button>
          ))}

          <span className="text-xs font-mono text-slate-500 uppercase tracking-wider ml-3">Source</span>
          {SOURCE_FILTERS.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setSource(value)}
              className={`px-3 py-1 text-xs font-mono border rounded transition-colors
                ${source === value
                  ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                  : 'border-tron-border text-slate-500 hover:border-tron-cyan/40 hover:text-slate-300'}`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIncludeDismissed((v) => !v)}
            className={`px-3 py-1 text-xs font-mono border rounded transition-colors flex items-center gap-1
              ${includeDismissed
                ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                : 'border-tron-border text-slate-500 hover:text-slate-300'}`}
            title="Include dismissed/archived alarms in the feed"
          >
            {includeDismissed ? <Eye size={12} /> : <EyeOff size={12} />}
            {includeDismissed ? 'Showing dismissed' : 'Hiding dismissed'}
          </button>
          <GlowButton
            size="sm"
            variant="ghost"
            onClick={() => clearDismissed.mutate()}
            disabled={clearDismissed.isPending}
            title="Permanently delete all dismissed alarms"
          >
            <Archive size={12} className="mr-1" />
            Archive dismissed
          </GlowButton>
        </div>
      </TronPanel>

      {/* ── Alarm table ────────────────────────────────────────────── */}
      <TronPanel className="overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <ShieldAlert size={32} className="text-tron-cyan/20 mx-auto mb-2 animate-pulse" />
            <p className="text-xs font-mono text-slate-600">Loading alarm feed…</p>
          </div>
        ) : sorted.length === 0 ? (
          <div className="p-8 text-center">
            <Bell size={32} className="text-tron-cyan/20 mx-auto mb-2" />
            <p className="text-xs font-mono text-slate-600">No alarms in view</p>
            <p className="text-xs font-mono text-slate-700 mt-1">
              {severity || source
                ? 'Adjust the filters above, or turn on dismissed-visibility to see archived alarms.'
                : 'Either nothing is firing (good) or no gateway integrations are configured. See Settings → Gateway Integrations.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-tron-border text-xs font-mono text-slate-500 uppercase tracking-wider">
                  <th className="py-2 px-3 w-6" />
                  <th className="py-2 px-2">Severity</th>
                  <th className="py-2 px-2">Source</th>
                  <th className="py-2 px-2">Message</th>
                  <th className="py-2 px-2">Device / From</th>
                  <th className="py-2 px-2">Count</th>
                  <th className="py-2 px-2">Last seen</th>
                  <th className="py-2 px-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((alm) => (
                  <AlarmRow
                    key={alm.id}
                    alarm={alm}
                    onAck={(id) => ack.mutate(id)}
                    onDismiss={(id) => dismiss.mutate(id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </TronPanel>

      {/* ── Footer copy ────────────────────────────────────────────── */}
      <p className="text-xs text-slate-600 font-mono flex items-center gap-2">
        <AlertOctagon size={12} />
        Alarms are deduplicated by source + signature + minute-bucket.
        A single attack firing hundreds of packets shows as one row with a count,
        not a feed flood. <span className="text-slate-500">Ack = seen, Dismiss = resolved, Archive = purge dismissed.</span>
      </p>
    </div>
  )
}

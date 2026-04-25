import { useState, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { getAuditLog, getChangeHistory } from '../api/claudeIntegration'
import { useSocket } from '../hooks/useSocket'
import type { StagedChange } from '../api/claudeIntegration'
import { TronPanel } from '../components/shared/TronPanel'
import { LoadingGrid } from '../components/shared/LoadingGrid'
import {
  Check, X, Sparkles, ChevronDown, ChevronRight,
  History, ClipboardList, Code2, Server
} from 'lucide-react'

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(status: string) {
  switch (status) {
    case 'approved': return 'text-status-online'
    case 'applied':  return 'text-tron-cyan'
    case 'rejected': return 'text-status-offline'
    default:         return 'text-yellow-400'
  }
}

function statusIcon(status: string) {
  switch (status) {
    case 'approved': return <Check size={12} />
    case 'applied':  return <Sparkles size={12} />
    case 'rejected': return <X size={12} />
    default:         return <ClipboardList size={12} />
  }
}

function actionColor(action: string) {
  if (action.includes('approve') || action.includes('apply')) return 'text-status-online'
  if (action.includes('reject') || action.includes('delete')) return 'text-status-offline'
  return 'text-tron-cyan'
}

// Humanise action slugs so the log reads as sentences rather than identifiers.
// Falls through to a prettified slug for unknown actions — new actions still
// show up, just without the curated label.
function actionLabel(action: string): string {
  const map: Record<string, string> = {
    save_settings: 'settings saved',
    save_scan_intervals: 'scan intervals saved',
    save_scan_credential: 'scan credential saved',
    delete_scan_credential: 'scan credential deleted',
    test_scan_credential: 'scan credential tested',
    trigger_openvas_scan: 'openvas scan triggered',
    trigger_job: 'job triggered',
    pause_job: 'job paused',
    resume_job: 'job resumed',
    trigger_analysis: 'analysis triggered',
    delete_analysis_report: 'analysis report deleted',
    approve_claude_change: 'claude change approved',
    reject_claude_change: 'claude change rejected',
    apply_claude_change: 'claude change applied',
    reset_openvas_start: 'openvas reset started',
    reset_openvas_success: 'openvas reset succeeded',
    reset_openvas_failed: 'openvas reset failed',
    openvas_auth_failed: 'openvas auth failed',
  }
  return map[action] || action.replace(/_/g, ' ')
}

// Pretty-print a detail object into summary lines. Hand-maps known action
// types to their most useful fields; unknown details fall back to a
// comma-joined key=value render so nothing is ever silently hidden.
function renderDetailLines(action: string, detail: any): string[] {
  if (!detail || typeof detail !== 'object') return []
  const d = detail

  switch (action) {
    case 'test_scan_credential': {
      const header = `${d.target_ip} as ${d.username} (${d.auth_type || 'password'}) — ${d.ok_count}/${d.host_count} ok`
      const failed = Array.isArray(d.results)
        ? d.results.filter((r: any) => !r.ok).slice(0, 6)
        : []
      const failLines = failed.map((r: any) => `  ✗ ${r.ip}: ${r.status}${r.detail ? ` — ${r.detail}` : ''}`)
      return [header, ...failLines]
    }
    case 'save_scan_credential':
      return [`${d.target_ip} as ${d.username} (${d.auth_type || 'password'})`]
    case 'delete_scan_credential':
      return [`id ${d.id}`]
    case 'trigger_openvas_scan':
      return [`device ${d.device_id}${d.ip ? ` (${d.ip})` : ''}`]
    case 'trigger_job':
    case 'pause_job':
    case 'resume_job':
      return [d.job_id || '']
    case 'save_scan_intervals':
      return [Object.entries(d).map(([k, v]) => `${k}=${v}`).join(', ')]
    case 'save_settings': {
      const lines: string[] = []
      if (Array.isArray(d.sections)) lines.push(`sections: ${d.sections.join(', ')}`)
      if (d.values && typeof d.values === 'object') {
        for (const [section, vals] of Object.entries(d.values as Record<string, any>)) {
          if (vals && typeof vals === 'object') {
            const pairs = Object.entries(vals).map(([k, v]) => `${k}=${v}`).join(', ')
            if (pairs) lines.push(`  ${section}: ${pairs}`)
          }
        }
      }
      return lines
    }
    case 'trigger_analysis':
      return [`period ${d.period_hours}h`]
    case 'delete_analysis_report':
      return [d.report_id || '']
    case 'reset_openvas_start':
    case 'reset_openvas_success':
      return [`container ${d.container || '—'} as ${d.username || '—'}`]
    case 'reset_openvas_failed':
      return [`container ${d.container || '—'}`, d.reason ? `reason: ${d.reason}` : '']
        .filter(Boolean) as string[]
    case 'openvas_auth_failed':
      return [d.reason || 'authentication rejected']
  }
  // Generic fallback.
  return Object.entries(d)
    .filter(([, v]) => v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) =>
      typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
        ? `${k}: ${v}`
        : `${k}: ${JSON.stringify(v)}`,
    )
    .slice(0, 6)
}

// ── Diff Viewer ───────────────────────────────────────────────────────────────

function DiffViewer({ diff }: { diff: string }) {
  return (
    <pre className="text-xs font-mono leading-5 overflow-x-auto whitespace-pre">
      {diff.split('\n').map((line, i) => {
        const cls =
          line.startsWith('+') && !line.startsWith('+++') ? 'text-status-online bg-green-950/40' :
          line.startsWith('-') && !line.startsWith('---') ? 'text-status-offline bg-red-950/40' :
          line.startsWith('@@') ? 'text-tron-cyan' :
          'text-slate-500'
        return (
          <span key={i} className={`block px-1 ${cls}`}>{line || ' '}</span>
        )
      })}
    </pre>
  )
}

// ── Change History Row ────────────────────────────────────────────────────────

function ChangeRow({ change }: { change: StagedChange }) {
  const [open, setOpen] = useState(false)
  const ctx = change.device_context || {}

  return (
    <div className="rounded border border-tron-border/50 bg-tron-dark overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-white/5 transition-colors"
      >
        <span className={`mt-0.5 flex-shrink-0 ${statusColor(change.status)}`}>
          {statusIcon(change.status)}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-mono font-semibold uppercase ${statusColor(change.status)}`}>
              {change.status}
            </span>
            <span className="text-xs text-slate-500 font-mono truncate">{change.device_id}</span>
            <span className="text-xs text-slate-600 font-mono ml-auto">
              {new Date(change.triggered_at).toLocaleString()}
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5 line-clamp-1">{change.reason}</p>
        </div>
        <span className="text-slate-600 flex-shrink-0 mt-0.5">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="border-t border-tron-border/30 p-3 space-y-3">
              {/* Device context */}
              {Object.keys(ctx).length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mb-1.5">
                    <Server size={11} /> Device Context
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs font-mono">
                    {(ctx as any).ip && (
                      <span className="text-slate-400">IP: <span className="text-tron-cyan">{(ctx as any).ip}</span></span>
                    )}
                    {(ctx as any).hostname && (
                      <span className="text-slate-400">Host: <span className="text-tron-cyan">{(ctx as any).hostname}</span></span>
                    )}
                    {(ctx as any).os_guess && (
                      <span className="text-slate-400">OS: <span className="text-slate-300">{(ctx as any).os_guess}</span></span>
                    )}
                    {Array.isArray((ctx as any).open_ports) && (ctx as any).open_ports.length > 0 && (
                      <span className="text-slate-400 col-span-2">
                        Ports: <span className="text-slate-300">{(ctx as any).open_ports.join(', ')}</span>
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Diff preview */}
              {change.diff_preview && (
                <div>
                  <div className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mb-1.5">
                    <Code2 size={11} /> Generated Diff
                  </div>
                  <div className="rounded bg-slate-950 border border-tron-border/30 max-h-64 overflow-auto">
                    <DiffViewer diff={change.diff_preview} />
                  </div>
                </div>
              )}

              {/* Files */}
              {change.generated_files?.length > 0 && (
                <div className="text-xs font-mono text-slate-500">
                  Files: {change.generated_files.map(f => (
                    <span key={f} className="text-tron-cyan ml-1">{f.split('/').pop()}</span>
                  ))}
                </div>
              )}

              {change.reviewed_at && (
                <div className="text-xs font-mono text-slate-600">
                  Reviewed: {new Date(change.reviewed_at).toLocaleString()}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

type Tab = 'history' | 'audit'

export function AuditLogPage() {
  const [tab, setTab] = useState<Tab>('history')
  const queryClient = useQueryClient()
  const { on } = useSocket()

  useEffect(() => {
    return on('claude:staged', () => {
      queryClient.invalidateQueries({ queryKey: ['claude-history'] })
      queryClient.invalidateQueries({ queryKey: ['audit-log'] })
    })
  }, [on, queryClient])

  const { data: history = [], isLoading: histLoading } = useQuery({
    queryKey: ['claude-history'],
    queryFn: getChangeHistory,
    refetchInterval: 30_000,
  })

  const { data: auditEntries = [], isLoading: auditLoading } = useQuery({
    queryKey: ['audit-log'],
    queryFn: getAuditLog,
    refetchInterval: 30_000,
  })

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'history', label: 'Change History', icon: <History size={13} /> },
    { id: 'audit',   label: 'Audit Log',      icon: <ClipboardList size={13} /> },
  ]

  return (
    <div className="h-full overflow-auto p-4">
      <TronPanel className="p-4">
        <div className="flex items-center gap-2 mb-4">
          <Sparkles size={14} className="text-tron-cyan" />
          <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider">
            Claude Integration
          </h2>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 mb-4 border-b border-tron-border/30 pb-0">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 -mb-px ${
                tab === t.id
                  ? 'text-tron-cyan border-tron-cyan'
                  : 'text-slate-500 border-transparent hover:text-slate-300'
              }`}
            >
              {t.icon} {t.label}
            </button>
          ))}
        </div>

        {/* Change History tab */}
        {tab === 'history' && (
          histLoading ? <LoadingGrid rows={4} /> :
          history.length === 0 ? (
            <p className="text-slate-500 font-mono text-sm">No staged changes yet.</p>
          ) : (
            <div className="space-y-2">
              {history.map((ch: StagedChange) => (
                <ChangeRow key={ch.id} change={ch} />
              ))}
            </div>
          )
        )}

        {/* Audit Log tab */}
        {tab === 'audit' && (
          auditLoading ? <LoadingGrid rows={4} /> :
          auditEntries.length === 0 ? (
            <p className="text-slate-500 font-mono text-sm">No audit entries yet.</p>
          ) : (
            <div className="space-y-2">
              {auditEntries.map((entry: any) => {
                const lines = renderDetailLines(entry.action, entry.detail)
                const isTestFail =
                  entry.action === 'test_scan_credential' && entry.detail?.all_ok === false
                return (
                  <div
                    key={entry.id}
                    className="flex items-start gap-3 p-3 rounded bg-tron-dark border border-tron-border/50"
                  >
                    <div className={`mt-0.5 flex-shrink-0 ${actionColor(entry.action)}`}>
                      {entry.action.includes('approve') || entry.action.includes('apply')
                        ? <Check size={14} />
                        : entry.action.includes('reject') || entry.action.includes('delete') || isTestFail
                        ? <X size={14} />
                        : <ClipboardList size={14} />
                      }
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs font-mono ${actionColor(entry.action)}`}>
                          {actionLabel(entry.action)}
                        </span>
                        {entry.actor && entry.actor !== 'user' && (
                          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-1.5 py-0.5 rounded bg-slate-800/60">
                            {entry.actor}
                          </span>
                        )}
                        <span className="text-xs text-slate-600 font-mono ml-auto">
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </div>
                      {/* Claude-specific short fields preserved for continuity */}
                      {entry.detail?.device_id && (
                        <div className="text-xs text-slate-500 font-mono mt-0.5">
                          Device: {entry.detail.device_id}
                        </div>
                      )}
                      {entry.detail?.files_applied?.length > 0 && (
                        <div className="text-xs text-tron-cyan font-mono mt-0.5">
                          Applied: {entry.detail.files_applied.map((f: string) => f.split('/').pop()).join(', ')}
                        </div>
                      )}
                      {/* Generic detail lines for every other action type */}
                      {lines.length > 0 && !entry.detail?.device_id && (
                        <div className="text-xs text-slate-400 font-mono mt-0.5 space-y-0.5">
                          {lines.map((line, i) => (
                            <div key={i} className="whitespace-pre">{line}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )
        )}
      </TronPanel>
    </div>
  )
}

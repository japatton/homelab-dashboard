import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, Trash2, Clock, AlertTriangle, CheckCircle, Zap } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

import client from '../api/client'
import { TronPanel } from '../components/shared/TronPanel'
import { GlowButton } from '../components/shared/GlowButton'

interface ReportPreview {
  id: string
  generated_at: string
  period_start: string
  period_end: string
  model: string | null
  status: 'completed' | 'failed' | 'running'
  duration_ms: number | null
  preview: string
}

interface ReportDetail extends ReportPreview {
  summary_md: string | null
  input_json: any
  raw_prompt: string | null
  raw_response: string | null
  error: string | null
}

function fmtTs(iso: string) {
  return new Date(iso).toLocaleString()
}

function fmtDuration(ms: number | null) {
  if (ms == null) return '—'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; icon: any; label: string }> = {
    completed: { cls: 'bg-status-online/10 text-status-online',   icon: CheckCircle,    label: 'completed' },
    failed:    { cls: 'bg-status-offline/10 text-status-offline', icon: AlertTriangle,  label: 'failed' },
    running:   { cls: 'bg-tron-cyan/10 text-tron-cyan animate-pulse', icon: Zap,        label: 'running' },
  }
  const m = map[status] ?? map.completed
  const Icon = m.icon
  return (
    <span className={`flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded-full ${m.cls}`}>
      <Icon size={10} /> {m.label}
    </span>
  )
}

export function AnalysisPage() {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)

  const { data: reports = [], isLoading } = useQuery<ReportPreview[]>({
    queryKey: ['analysis-reports'],
    queryFn: async () => (await client.get('/analysis/reports')).data,
    refetchInterval: 15_000,
  })

  const { data: detail } = useQuery<ReportDetail>({
    queryKey: ['analysis-report', selected],
    queryFn: async () => (await client.get(`/analysis/reports/${selected}`)).data,
    enabled: !!selected,
  })

  const trigger = useMutation({
    mutationFn: async () => client.post('/analysis/trigger'),
    onSuccess: () => {
      // Poll list more aggressively for ~30s to catch the new report landing.
      qc.invalidateQueries({ queryKey: ['analysis-reports'] })
    },
  })

  const del = useMutation({
    mutationFn: async (id: string) => client.delete(`/analysis/reports/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analysis-reports'] })
      if (selected) setSelected(null)
    },
  })

  return (
    <div className="h-full overflow-hidden flex gap-4 p-4">
      {/* ── Reports list ─────────────────────────────────────────── */}
      <TronPanel className="w-80 flex-none p-4 flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider">Analysis Reports</h2>
          <GlowButton
            size="sm"
            onClick={() => trigger.mutate()}
            disabled={trigger.isPending}
            title="Generate a new report using the last 24h of data"
          >
            <Play size={12} className="mr-1" /> Run Now
          </GlowButton>
        </div>

        {trigger.isPending && (
          <div className="mb-2 text-xs font-mono text-tron-cyan animate-pulse">
            Dispatched — new report will appear below once the model responds.
          </div>
        )}

        <div className="flex-1 overflow-auto space-y-1 pr-1">
          {isLoading && <div className="text-xs font-mono text-slate-500">Loading…</div>}
          {!isLoading && reports.length === 0 && (
            <div className="text-xs font-mono text-slate-500 italic p-2">
              No reports yet. Click Run Now to generate the first one, or wait for the daily schedule to fire.
            </div>
          )}
          {reports.map((r) => (
            <button
              key={r.id}
              onClick={() => setSelected(r.id)}
              className={`w-full text-left p-2 border rounded transition-colors ${
                selected === r.id
                  ? 'border-tron-cyan/50 bg-tron-cyan/5'
                  : 'border-tron-border/30 hover:border-tron-cyan/30 hover:bg-tron-cyan/5'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-slate-300">{fmtTs(r.generated_at)}</span>
                <StatusBadge status={r.status} />
              </div>
              <div className="text-[10px] font-mono text-slate-500 flex items-center gap-2">
                <Clock size={9} /> {fmtDuration(r.duration_ms)}
                <span className="truncate">{r.model ?? ''}</span>
              </div>
              <div className="text-xs text-slate-400 mt-1 line-clamp-2">
                {r.preview || '(no content)'}
              </div>
            </button>
          ))}
        </div>
      </TronPanel>

      {/* ── Report detail ────────────────────────────────────────── */}
      <TronPanel className="flex-1 p-4 flex flex-col overflow-hidden">
        {!selected && (
          <div className="flex items-center justify-center h-full text-slate-500 font-mono text-sm">
            Select a report to view details
          </div>
        )}

        {selected && !detail && (
          <div className="text-xs font-mono text-slate-500">Loading report…</div>
        )}

        {selected && detail && (
          <>
            <div className="flex items-center justify-between mb-3 pb-3 border-b border-tron-border/30">
              <div>
                <div className="text-sm font-mono text-slate-200">
                  {fmtTs(detail.generated_at)}
                </div>
                <div className="text-xs font-mono text-slate-500 mt-0.5">
                  Window: {fmtTs(detail.period_start)} → {fmtTs(detail.period_end)} · Model: {detail.model ?? '—'} · {fmtDuration(detail.duration_ms)}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <StatusBadge status={detail.status} />
                <button
                  onClick={() => del.mutate(detail.id)}
                  className="text-slate-500 hover:text-status-offline transition-colors p-1"
                  title="Delete report"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-auto pr-2">
              {detail.status === 'failed' && (
                <div className="p-3 border border-status-offline/40 rounded bg-status-offline/5 mb-3">
                  <div className="text-xs font-mono text-status-offline uppercase tracking-wider mb-1">Error</div>
                  <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{detail.error}</pre>
                </div>
              )}

              {detail.summary_md && (
                <article className="prose prose-invert prose-sm max-w-none font-mono
                                    prose-headings:text-tron-cyan prose-headings:font-mono prose-headings:uppercase prose-headings:tracking-wider
                                    prose-strong:text-slate-100
                                    prose-a:text-tron-cyan
                                    prose-code:text-tron-cyan prose-code:bg-tron-dark prose-code:px-1 prose-code:rounded
                                    prose-li:text-slate-300
                                    prose-p:text-slate-300">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{detail.summary_md}</ReactMarkdown>
                </article>
              )}

              {/* Input snapshot — collapsed by default so the brief stays the focus */}
              <details className="mt-6 border border-tron-border/30 rounded">
                <summary className="cursor-pointer px-3 py-2 text-xs font-mono text-slate-400 uppercase tracking-wider hover:text-tron-cyan">
                  Input data (JSON sent to model)
                </summary>
                <pre className="p-3 text-xs font-mono text-slate-400 overflow-auto max-h-96 bg-tron-dark">
                  {JSON.stringify(detail.input_json, null, 2)}
                </pre>
              </details>
            </div>
          </>
        )}
      </TronPanel>
    </div>
  )
}

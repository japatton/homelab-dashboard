import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, ChevronDown, ChevronUp } from 'lucide-react'
import { getLatency, type LatencyResponse } from '../../api/network'

/**
 * Floating latency mini-chart overlaid on the network map.
 *
 * Pulls gateway-latency samples every 30s and renders them as a compact
 * SVG line graph. No charting dependency — keeps the frontend lean.
 */
const POLL_MS = 30_000
const DEFAULT_WINDOW_MINUTES = 60

const CHART_W = 260
const CHART_H = 72
const PAD_X = 4
const PAD_Y = 6

export function LatencyChart() {
  const [collapsed, setCollapsed] = useState(false)
  const [windowMinutes, setWindowMinutes] = useState(DEFAULT_WINDOW_MINUTES)

  const { data } = useQuery<LatencyResponse>({
    queryKey: ['latency', windowMinutes],
    queryFn: () => getLatency({ window_minutes: windowMinutes }),
    refetchInterval: POLL_MS,
  })

  const { path, current, min, max, avg } = useMemo(() => {
    const samples = (data?.samples ?? []).filter(
      (s): s is { ts: string; latency_ms: number } => s.latency_ms != null,
    )
    if (samples.length === 0) {
      return { path: '', current: null, min: null, max: null, avg: null }
    }
    const values = samples.map((s) => s.latency_ms)
    const mn = Math.min(...values)
    const mx = Math.max(...values)
    const range = mx - mn || 1
    const step = (CHART_W - PAD_X * 2) / Math.max(samples.length - 1, 1)
    const pts = samples.map((s, i) => {
      const x = PAD_X + i * step
      const y = CHART_H - PAD_Y - ((s.latency_ms - mn) / range) * (CHART_H - PAD_Y * 2)
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    const avgVal = values.reduce((a, b) => a + b, 0) / values.length
    return {
      path: 'M' + pts.join(' L'),
      current: values[values.length - 1],
      min: mn,
      max: mx,
      avg: avgVal,
    }
  }, [data])

  const label = data?.device_label ?? 'Gateway'

  return (
    <div
      className="absolute bottom-4 left-4 z-10 bg-tron-panel border border-tron-border rounded-lg font-mono shadow-lg"
      style={{ width: collapsed ? 160 : CHART_W + 16, transition: 'width 0.2s ease' }}
    >
      <button
        type="button"
        onClick={() => setCollapsed((v) => !v)}
        className="w-full flex items-center justify-between px-2 py-1.5 text-tron-cyan text-xs hover:bg-tron-border/30 rounded-t-lg"
      >
        <span className="flex items-center gap-1.5">
          <Activity size={12} />
          <span>Latency · {label}</span>
        </span>
        {collapsed ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
      </button>

      {!collapsed && (
        <div className="px-2 pb-2">
          {path ? (
            <>
              <svg
                width={CHART_W}
                height={CHART_H}
                viewBox={`0 0 ${CHART_W} ${CHART_H}`}
                className="block"
              >
                <defs>
                  <linearGradient id="latFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="rgba(0,229,255,0.35)" />
                    <stop offset="100%" stopColor="rgba(0,229,255,0)" />
                  </linearGradient>
                </defs>
                {/* Baseline grid */}
                <line
                  x1={PAD_X}
                  y1={CHART_H / 2}
                  x2={CHART_W - PAD_X}
                  y2={CHART_H / 2}
                  stroke="rgba(0,229,255,0.08)"
                  strokeDasharray="2 3"
                />
                {/* Area fill */}
                <path
                  d={`${path} L${CHART_W - PAD_X},${CHART_H - PAD_Y} L${PAD_X},${CHART_H - PAD_Y} Z`}
                  fill="url(#latFill)"
                />
                {/* Line */}
                <path
                  d={path}
                  fill="none"
                  stroke="#00e5ff"
                  strokeWidth={1.5}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              </svg>
              <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                <span>
                  now <span className="text-tron-cyan">{current?.toFixed(1)}ms</span>
                </span>
                <span>min {min?.toFixed(1)}ms</span>
                <span>avg {avg?.toFixed(1)}ms</span>
                <span>max {max?.toFixed(1)}ms</span>
              </div>
              <div className="flex gap-1 mt-1.5 text-[10px]">
                {[15, 60, 240, 1440].map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setWindowMinutes(m)}
                    className={`flex-1 px-1 py-0.5 rounded border ${
                      windowMinutes === m
                        ? 'border-tron-cyan text-tron-cyan'
                        : 'border-tron-border text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    {m < 60 ? `${m}m` : m < 1440 ? `${m / 60}h` : '24h'}
                  </button>
                ))}
              </div>
            </>
          ) : (
            <div className="text-[10px] text-slate-500 py-3 text-center">
              No samples yet — waiting for first poll…
            </div>
          )}
        </div>
      )}
    </div>
  )
}

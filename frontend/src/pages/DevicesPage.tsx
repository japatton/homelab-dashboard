import { useEffect, useRef, useState } from 'react'
import { useDevices } from '../hooks/useDevices'
import { useSocket } from '../hooks/useSocket'
import { StatusIndicator } from '../components/shared/StatusIndicator'
import { LoadingGrid } from '../components/shared/LoadingGrid'
import { TronPanel } from '../components/shared/TronPanel'
import { useToast } from '../components/shared/Toast'
import { ExternalLink, Search, Zap, Loader2, CheckCircle2, AlertOctagon } from 'lucide-react'
import client from '../api/client'
import type { Device } from '../types/device'

// ──────────────────────────────────────────────────────────────────────────────
// DevicesPage
//
// Canonical home for the "run a vuln scan on this device" action — previously
// only reachable via the topology slide-out panel, which required the user to
// know where on the 2D map their device was. Adds a "Scan" column with per-row
// state tracking so clicking doesn't silently vanish: the button shows
// scanning → done / failed and a toast surfaces the outcome.
//
// Scan state lives *in the row*, not in a global store — the backend's
// POST /api/vulns/scan/{device_id} returns immediately with 202 semantics
// (the real scan takes minutes). We pessimistically set a 90-second "queued"
// window before reverting to idle so the UI doesn't lie about the scanner
// still being busy when it's not.
// ──────────────────────────────────────────────────────────────────────────────

type ScanState =
  | { kind: 'idle' }
  | { kind: 'starting' }      // HTTP request in flight
  | { kind: 'queued' }        // queued → scanner will pick it up
  | { kind: 'running' }       // observed scan_result for this device
  | { kind: 'done'; at: number }
  | { kind: 'failed'; reason: string }

// Hard ceiling on how long a row stays in "queued" state after the click;
// prevents a forever-spinner if the backend never emits a result event.
const QUEUED_TTL_MS = 90_000

function ScanButton({
  device,
  state,
  onStart,
}: {
  device: Device
  state: ScanState
  onStart: () => void
}) {
  if (!device.ip) {
    // No IP = nothing to scan against. Disable with an explanatory tooltip
    // rather than hiding, so the column alignment stays consistent.
    return (
      <button
        disabled
        title="No IP address — scan requires an IPv4/IPv6 target"
        className="text-slate-600 font-mono text-[11px] px-1.5 py-0.5 border border-tron-border/30 rounded inline-flex items-center gap-1 cursor-not-allowed"
      >
        <Zap size={10} /> Scan
      </button>
    )
  }

  switch (state.kind) {
    case 'starting':
    case 'queued':
    case 'running':
      return (
        <span className="text-tron-cyan/90 font-mono text-[11px] px-1.5 py-0.5 border border-tron-cyan/40 rounded inline-flex items-center gap-1 bg-tron-cyan/5">
          <Loader2 size={10} className="animate-spin" />
          {state.kind === 'starting' ? 'queueing' : state.kind}
        </span>
      )
    case 'done':
      return (
        <span className="text-status-online font-mono text-[11px] px-1.5 py-0.5 border border-status-online/40 rounded inline-flex items-center gap-1">
          <CheckCircle2 size={10} /> done
        </span>
      )
    case 'failed':
      return (
        <button
          onClick={onStart}
          title={state.reason}
          className="text-status-offline font-mono text-[11px] px-1.5 py-0.5 border border-status-offline/40 rounded hover:bg-status-offline/10 inline-flex items-center gap-1 transition-colors"
        >
          <AlertOctagon size={10} /> retry
        </button>
      )
    case 'idle':
    default:
      return (
        <button
          onClick={onStart}
          className="text-tron-cyan font-mono text-[11px] px-1.5 py-0.5 border border-tron-cyan/40 rounded hover:bg-tron-cyan/10 hover:border-tron-cyan inline-flex items-center gap-1 transition-colors"
        >
          <Zap size={10} /> Scan
        </button>
      )
  }
}

function DeviceRow({
  device,
  scanState,
  onScan,
}: {
  device: Device
  scanState: ScanState
  onScan: (device: Device) => void
}) {
  const launchService = device.services.find((s) => s.launch_url)
  return (
    <tr className="border-b border-tron-border/30 hover:bg-tron-cyan/5 transition-colors">
      <td className="px-3 py-2.5 flex items-center gap-2">
        <StatusIndicator status={device.status} size="sm" />
        <span className="text-slate-200 text-sm font-mono truncate max-w-36">
          {device.label ?? device.hostname ?? device.ip ?? device.id}
        </span>
      </td>
      <td className="px-3 py-2.5 text-slate-400 text-xs font-mono">{device.ip ?? '—'}</td>
      <td className="px-3 py-2.5 text-slate-400 text-xs font-mono">{device.mac ?? '—'}</td>
      <td className="px-3 py-2.5">
        <span className="text-xs font-mono text-tron-cyan/80 bg-tron-cyan/10 border border-tron-cyan/20 rounded px-1.5 py-0.5">
          {device.device_type}
        </span>
      </td>
      <td className="px-3 py-2.5 text-xs font-mono text-slate-400">{device.services.length}</td>
      <td className="px-3 py-2.5">
        {(device.vuln_summary.critical > 0 || device.vuln_summary.high > 0) && (
          <span className={`text-xs font-mono font-bold ${device.vuln_summary.critical > 0 ? 'text-red-400' : 'text-orange-400'}`}>
            {device.vuln_summary.critical > 0 ? `${device.vuln_summary.critical}C` : `${device.vuln_summary.high}H`}
          </span>
        )}
      </td>
      <td className="px-3 py-2.5">
        <ScanButton device={device} state={scanState} onStart={() => onScan(device)} />
      </td>
      <td className="px-3 py-2.5">
        {launchService && (
          <a
            href={launchService.launch_url!}
            target="_blank"
            rel="noopener noreferrer"
            className="text-tron-cyan hover:text-white transition-colors"
          >
            <ExternalLink size={13} />
          </a>
        )}
      </td>
    </tr>
  )
}

export function DevicesPage() {
  const [search, setSearch] = useState('')
  const { devices, isLoading } = useDevices({ search: search || undefined })
  const toast = useToast()
  const { on } = useSocket()

  // Keyed by device.id. Mutating via functional setState so concurrent
  // scan triggers (which the user can do — different rows are independent)
  // don't race each other.
  const [scanStates, setScanStates] = useState<Record<string, ScanState>>({})

  const setRow = (id: string, s: ScanState) =>
    setScanStates((prev) => ({ ...prev, [id]: s }))

  // Listen for socket events that confirm the scheduled scan ran. The
  // backend emits `scan:complete` with `device_id` when a per-device
  // scan finishes; if we miss the event (socket reconnect), the 90s TTL
  // below falls us back to idle so the UI stops lying.
  //
  // Ref-pattern: the callback closes over `toast`, which is a stable API
  // object, so re-registration churn is near-zero. We still wrap the
  // subscribe/unsubscribe in useEffect for proper lifecycle cleanup.
  const toastRef = useRef(toast)
  toastRef.current = toast
  useEffect(() => {
    const off = on<{ scan_type?: string; error?: string | null; device_id?: string }>(
      'scan:complete',
      (data) => {
        if (!data.device_id) return
        if (data.error) {
          setRow(data.device_id, { kind: 'failed', reason: data.error })
          toastRef.current.error('Scan failed', data.error)
        } else {
          setRow(data.device_id, { kind: 'done', at: Date.now() })
          toastRef.current.ok('Scan complete', 'Results posted to the Vulnerabilities page')
        }
      },
    )
    return off
  }, [on])

  const onScan = async (device: Device) => {
    setRow(device.id, { kind: 'starting' })
    try {
      await client.post(`/vulns/scan/${device.id}`)
      setRow(device.id, { kind: 'queued' })
      toast.info('Scan queued', `${device.label ?? device.hostname ?? device.ip} · OpenVAS`)

      // TTL fallback so rows don't get stuck spinning forever if the
      // completion socket event gets lost somewhere.
      setTimeout(() => {
        setScanStates((prev) => {
          const s = prev[device.id]
          if (!s || s.kind !== 'queued') return prev
          return { ...prev, [device.id]: { kind: 'idle' } }
        })
      }, QUEUED_TTL_MS)
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e?.message || 'request failed'
      setRow(device.id, { kind: 'failed', reason: msg })
      toast.error('Scan request failed', msg)
    }
  }

  return (
    <div className="h-full overflow-auto p-4">
      <TronPanel className="h-full flex flex-col">
        <div className="flex items-center gap-3 p-3 border-b border-tron-border">
          <div className="relative flex-1 max-w-xs">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search devices..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-tron-dark border border-tron-border rounded text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-tron-cyan/50"
            />
          </div>
          <span className="text-xs font-mono text-slate-500">{devices.length} devices</span>
        </div>

        {isLoading ? (
          <div className="p-4"><LoadingGrid rows={5} /></div>
        ) : (
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-tron-border text-xs font-mono text-slate-500 uppercase tracking-wider sticky top-0 bg-tron-panel">
                  {['Device', 'IP', 'MAC', 'Type', 'Services', 'Vulns', 'Scan', ''].map((h) => (
                    <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <DeviceRow
                    key={d.id}
                    device={d}
                    scanState={scanStates[d.id] ?? { kind: 'idle' }}
                    onScan={onScan}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </TronPanel>
    </div>
  )
}


import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play, Pause, RefreshCw, Clock, Save, Check, X, Plus, Trash2, Zap, Brain, AlertTriangle, KeyRound } from 'lucide-react'

import client from '../api/client'
import { TronPanel } from '../components/shared/TronPanel'
import { GlowButton } from '../components/shared/GlowButton'
import { useScanSchedule } from '../hooks/useScanSchedule'
import { useSocket } from '../hooks/useSocket'

// ── Job rows shown in the Scheduler panel ────────────────────────────────────
const SCHEDULER_JOBS: { id: string; label: string }[] = [
  { id: 'nmap_scan', label: 'Nmap Scan' },
  { id: 'unifi_poll', label: 'UniFi Poll' },
  { id: 'opnsense_poll', label: 'OPNsense Poll' },
  { id: 'firewalla_poll', label: 'Firewalla Poll' },
  { id: 'openvas_scan', label: 'OpenVAS Scan' },
  { id: 'latency_poll', label: 'Latency Poll' },
]

function fmtNextRun(iso: string | null | undefined) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

// =============================================================================
// Scan Intervals card — includes openvas hours now
// =============================================================================

function ScanIntervalsCard({ scheduler }: { scheduler: any }) {
  const qc = useQueryClient()
  // Controlled inputs seeded from server config, re-synced whenever the
  // settings query refetches (previously defaultValue only applied at mount
  // and never updated after a save).
  const [nmap, setNmap] = useState<number>(scheduler?.nmap_interval_minutes ?? 15)
  const [unifi, setUnifi] = useState<number>(scheduler?.unifi_poll_interval_seconds ?? 30)
  const [openvas, setOpenvas] = useState<number>(scheduler?.openvas_interval_hours ?? 24)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (scheduler?.nmap_interval_minutes != null) setNmap(scheduler.nmap_interval_minutes)
    if (scheduler?.unifi_poll_interval_seconds != null) setUnifi(scheduler.unifi_poll_interval_seconds)
    if (scheduler?.openvas_interval_hours != null) setOpenvas(scheduler.openvas_interval_hours)
  }, [scheduler?.nmap_interval_minutes, scheduler?.unifi_poll_interval_seconds, scheduler?.openvas_interval_hours])

  const save = useMutation({
    mutationFn: async () => {
      const payload = {
        nmap_minutes: nmap,
        unifi_seconds: unifi,
        openvas_hours: openvas,
      }
      return client.put('/scheduler/intervals', payload)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      qc.invalidateQueries({ queryKey: ['scheduler-status'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
  })

  return (
    <TronPanel className="p-4">
      <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider mb-4">Scan Intervals</h2>
      <div className="grid grid-cols-3 gap-4">
        <label className="block">
          <span className="text-xs font-mono text-slate-400">Nmap (minutes)</span>
          <input type="number" min={1}
            value={nmap}
            onChange={(e) => setNmap(Number(e.target.value))}
            className="mt-1 w-full px-3 py-1.5 bg-tron-dark border border-tron-border rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block">
          <span className="text-xs font-mono text-slate-400">UniFi poll (seconds)</span>
          <input type="number" min={5}
            value={unifi}
            onChange={(e) => setUnifi(Number(e.target.value))}
            className="mt-1 w-full px-3 py-1.5 bg-tron-dark border border-tron-border rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block">
          <span className="text-xs font-mono text-slate-400">OpenVAS (hours)</span>
          <input type="number" min={1}
            value={openvas}
            onChange={(e) => setOpenvas(Number(e.target.value))}
            className="mt-1 w-full px-3 py-1.5 bg-tron-dark border border-tron-border rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <GlowButton size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
          <RefreshCw size={12} className="mr-1" />
          Save Intervals
        </GlowButton>
        {saved && <span className="text-xs font-mono text-status-online animate-pulse">Saved</span>}
      </div>
    </TronPanel>
  )
}

// =============================================================================
// Integration Credentials — UniFi / Elasticsearch / OpenVAS
// Uses the existing POST /api/setup/complete to PATCH individual sections plus
// POST /api/setup/test-<service> to verify reachability.
// =============================================================================

type TestStatus = 'idle' | 'testing' | 'ok' | 'fail'

function useTestStatus() {
  const [status, setStatus] = useState<TestStatus>('idle')
  const [detail, setDetail] = useState<string>('')
  return { status, detail, setStatus, setDetail }
}

function StatusPill({ status, detail }: { status: TestStatus; detail: string }) {
  if (status === 'idle') return null
  const cls =
    status === 'ok' ? 'text-status-online' :
    status === 'fail' ? 'text-status-offline' :
    'text-slate-400'
  const icon =
    status === 'ok' ? <Check size={12} /> :
    status === 'fail' ? <X size={12} /> :
    <Zap size={12} className="animate-pulse" />
  return (
    <span className={`flex items-center gap-1 text-xs font-mono ${cls}`}>
      {icon} {detail || status}
    </span>
  )
}

function CredSection({
  title,
  children,
  test,
  save,
  testStatus,
}: {
  title: string
  children: React.ReactNode
  test: () => void
  save: () => void
  testStatus: ReturnType<typeof useTestStatus>
}) {
  return (
    <div className="border border-tron-border/40 rounded p-3 space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-mono text-tron-cyan uppercase tracking-wider">{title}</h3>
        <StatusPill status={testStatus.status} detail={testStatus.detail} />
      </div>
      <div className="grid grid-cols-2 gap-2">{children}</div>
      <div className="flex items-center gap-2 pt-1">
        <GlowButton size="sm" variant="ghost" onClick={test}>
          <Zap size={12} className="mr-1" /> Test
        </GlowButton>
        <GlowButton size="sm" onClick={save}>
          <Save size={12} className="mr-1" /> Save
        </GlowButton>
      </div>
    </div>
  )
}

function TextField({
  label, value, onChange, type = 'text', placeholder,
}: { label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string }) {
  return (
    <label className="block">
      <span className="text-[10px] font-mono text-slate-500 uppercase">{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
      />
    </label>
  )
}

// ── Rotate OpenVAS Admin Password modal ──────────────────────────────────────
// The `immauss/openvas` image only reads PASSWORD on first boot with a fresh
// volume. Rotating is therefore destructive: we stop the container, remove
// its named volume, and recreate with a new env var. The platform auto-
// manages the password (generated server-side, stored in config, never
// shown to the user), so this modal is a single "Rotate Now" button wired
// to POST /setup/rotate-openvas — then it follows progress on the
// `openvas:reset` socket channel until the flow hits `ready` or `error`.
type ResetStage = 'idle' | 'stopping' | 'wiping' | 'starting' | 'warmup' | 'ready' | 'error'

function ResetOpenVASModal({
  open,
  currentUser,
  onClose,
}: {
  open: boolean
  currentUser: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const { on } = useSocket()

  const [stage, setStage] = useState<ResetStage>('idle')
  const [percent, setPercent] = useState(0)
  const [message, setMessage] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  // Reset local progress state every time the modal reopens so a previous
  // run's "ready"/"error" doesn't bleed into the next one.
  useEffect(() => {
    if (open) {
      setStage('idle')
      setPercent(0)
      setMessage('')
      setError(null)
      setStarting(false)
    }
  }, [open])

  // Listen to the server's progress events while the modal is open. We keep
  // the listener attached for the whole lifetime of the modal so reconnects
  // during the 5–10 min warmup don't drop events we needed.
  useEffect(() => {
    if (!open) return
    const off = on<{ stage: ResetStage; percent: number; message: string; error: string | null }>(
      'openvas:reset',
      (data) => {
        setStage(data.stage)
        setPercent(data.percent)
        setMessage(data.message)
        if (data.error) setError(data.error)
        if (data.stage === 'ready') {
          // Refresh settings so the parent form picks up the new stored state.
          qc.invalidateQueries({ queryKey: ['settings'] })
        }
      },
    )
    return off
  }, [open, on, qc])

  if (!open) return null

  const running = starting || (stage !== 'idle' && stage !== 'ready' && stage !== 'error')

  const submit = async () => {
    setError(null)
    setStarting(true)
    setStage('stopping')
    setPercent(1)
    setMessage('submitting rotation request')
    try {
      await client.post('/setup/rotate-openvas', { username: currentUser || 'admin' })
    } catch (e: any) {
      const msg = e?.response?.data?.detail || e?.message || 'failed to start rotation'
      setError(msg)
      setStage('error')
      setPercent(0)
    } finally {
      setStarting(false)
    }
  }

  const barColor =
    stage === 'error' ? 'bg-status-offline'
    : stage === 'ready' ? 'bg-status-online'
    : 'bg-tron-cyan'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <TronPanel className="w-full max-w-lg p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-tron-cyan font-mono text-sm uppercase tracking-wider flex items-center gap-2">
            <KeyRound size={14} /> Rotate OpenVAS Admin Password
          </h3>
          <button
            onClick={onClose}
            disabled={running}
            className="text-slate-500 hover:text-slate-300 disabled:opacity-30"
          >
            <X size={16} />
          </button>
        </div>

        <div className="flex gap-2 p-2 border border-amber-500/40 rounded bg-amber-500/5">
          <AlertTriangle size={14} className="text-amber-400 flex-none mt-0.5" />
          <div className="text-xs font-mono text-amber-200/90 leading-relaxed">
            This stops the <span className="text-amber-300">homelab-openvas</span> container,
            <span className="text-amber-300"> deletes its data volume</span> (NVT feeds, scan
            history, reports), and recreates it with a newly-generated admin password. The
            platform stores the password for you — you never see or need to type it.
            First-boot NVT sync takes <span className="text-amber-300">5–10 minutes</span>;
            the modal will track progress. Running scans will be interrupted.
          </div>
        </div>

        {stage === 'idle' || stage === 'error' ? (
          <div className="space-y-3">
            <div className="p-3 rounded border border-tron-border/50 bg-tron-dark/40 font-mono text-xs text-slate-300 leading-relaxed">
              <div className="flex items-center gap-2 text-tron-cyan mb-1">
                <KeyRound size={11} /> Auto-generated password
              </div>
              <p className="text-slate-400">
                A 32-character random password will be generated server-side and
                stored in <span className="text-slate-300">config.yml</span>.
                The admin username stays as{' '}
                <span className="text-tron-cyan">{currentUser || 'admin'}</span>.
              </p>
            </div>
            {error && (
              <p className="text-xs font-mono text-status-offline break-words">
                {error}
              </p>
            )}
            <div className="flex items-center justify-end gap-2 pt-1">
              <GlowButton size="sm" variant="ghost" onClick={onClose}>Cancel</GlowButton>
              <GlowButton size="sm" onClick={submit}>
                <RefreshCw size={12} className="mr-1" /> Rotate Now
              </GlowButton>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="h-2 w-full bg-tron-dark rounded overflow-hidden border border-tron-border">
              <div
                className={`h-full ${barColor} transition-all duration-500`}
                style={{ width: `${Math.max(2, Math.min(100, percent))}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="uppercase tracking-wider text-slate-400">{stage}</span>
              <span className="text-slate-500">{percent}%</span>
            </div>
            <p className="text-xs font-mono text-slate-300 break-words min-h-[2em]">
              {message || '…'}
            </p>
            {stage === 'ready' && (
              <p className="text-xs font-mono text-status-online">
                Done. OpenVAS is authenticating with the new credentials.
              </p>
            )}
            {/* Errors surface in the form view — the error branch re-renders
                the input form (with the error shown inline) so the user can
                retry with different creds without reopening the modal. */}
            <div className="flex items-center justify-end gap-2 pt-1">
              <GlowButton
                size="sm"
                variant="ghost"
                onClick={onClose}
                disabled={running}
              >
                {stage === 'ready' ? 'Close' : 'Close (runs in background)'}
              </GlowButton>
            </div>
          </div>
        )}
      </TronPanel>
    </div>
  )
}

// =============================================================================
// Gateway Integrations — OPNsense + Firewalla
// Separate card from UniFi/ES/OpenVAS because these are "edge gateway" flavors
// that share semantics (feed devices + alarms) but each has its own test probe
// and config shape. Keeping them out of IntegrationsCard also keeps the UniFi
// card from growing a "which gateway are you using?" toggle.
// =============================================================================

function GatewayIntegrationsCard({ settings }: { settings: any }) {
  const qc = useQueryClient()

  // ── OPNsense ─────────────────────────────────────────────────────
  const [opn, setOpn] = useState({
    enabled: settings?.opnsense?.enabled ?? false,
    url: settings?.opnsense?.url ?? '',
    api_key: settings?.opnsense?.api_key ?? '',
    api_secret: '',           // blank = "(unchanged)"
    verify_ssl: settings?.opnsense?.verify_ssl ?? false,
    ids_enabled: settings?.opnsense?.ids_enabled ?? false,
    poll_interval_seconds: settings?.opnsense?.poll_interval_seconds ?? 60,
  })
  const opnTest = useTestStatus()
  const [opnSecretStored, setOpnSecretStored] = useState(false)

  // ── Firewalla ────────────────────────────────────────────────────
  const [fw, setFw] = useState({
    enabled: settings?.firewalla?.enabled ?? false,
    mode: (settings?.firewalla?.mode as 'msp' | 'local') ?? 'msp',
    msp_domain: settings?.firewalla?.msp_domain ?? '',
    msp_token: '',            // blank = "(unchanged)"
    local_url: settings?.firewalla?.local_url ?? '',
    local_token: '',          // blank = "(unchanged)"
    verify_ssl: settings?.firewalla?.verify_ssl ?? false,
    alarms_enabled: settings?.firewalla?.alarms_enabled ?? true,
    poll_interval_seconds: settings?.firewalla?.poll_interval_seconds ?? 120,
  })
  const fwTest = useTestStatus()
  const [fwMspTokenStored, setFwMspTokenStored] = useState(false)
  const [fwLocalTokenStored, setFwLocalTokenStored] = useState(false)

  // Re-hydrate from server once settings arrive. Mirror the pattern
  // IntegrationsCard uses: preserve secret-input emptiness so "(unchanged)"
  // works across saves, but capture a boolean "stored?" flag from the
  // masked string the API returns.
  useEffect(() => {
    if (!settings) return
    if (settings.opnsense) {
      const s = settings.opnsense
      setOpn((v) => ({
        ...v,
        enabled: !!s.enabled,
        url: s.url ?? v.url,
        api_key: s.api_key ?? v.api_key,
        verify_ssl: !!s.verify_ssl,
        ids_enabled: !!s.ids_enabled,
        poll_interval_seconds: s.poll_interval_seconds ?? v.poll_interval_seconds,
      }))
      setOpnSecretStored(Boolean(s.api_secret))
    }
    if (settings.firewalla) {
      const s = settings.firewalla
      setFw((v) => ({
        ...v,
        enabled: !!s.enabled,
        mode: s.mode ?? v.mode,
        msp_domain: s.msp_domain ?? v.msp_domain,
        local_url: s.local_url ?? v.local_url,
        verify_ssl: !!s.verify_ssl,
        alarms_enabled: !!s.alarms_enabled,
        poll_interval_seconds: s.poll_interval_seconds ?? v.poll_interval_seconds,
      }))
      setFwMspTokenStored(Boolean(s.msp_token))
      setFwLocalTokenStored(Boolean(s.local_token))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    settings?.opnsense?.enabled, settings?.opnsense?.url, settings?.opnsense?.api_key,
    settings?.opnsense?.verify_ssl, settings?.opnsense?.ids_enabled,
    settings?.opnsense?.poll_interval_seconds, settings?.opnsense?.api_secret,
    settings?.firewalla?.enabled, settings?.firewalla?.mode,
    settings?.firewalla?.msp_domain, settings?.firewalla?.local_url,
    settings?.firewalla?.verify_ssl, settings?.firewalla?.alarms_enabled,
    settings?.firewalla?.poll_interval_seconds,
    settings?.firewalla?.msp_token, settings?.firewalla?.local_token,
  ])

  async function run(fn: () => Promise<any>, t: ReturnType<typeof useTestStatus>, label: string) {
    t.setStatus('testing'); t.setDetail('')
    try {
      const r = await fn()
      t.setStatus('ok'); t.setDetail(label)
      return r
    } catch (e: any) {
      t.setStatus('fail'); t.setDetail(e?.response?.data?.detail || e?.message || 'failed')
    }
  }

  const saveSection = async (key: string, body: any) => {
    await client.post('/setup/complete', { [key]: body })
    qc.invalidateQueries({ queryKey: ['settings'] })
  }

  // Strip blanks from the outgoing save so we don't overwrite stored
  // secrets with empty strings. Backend `/setup/complete` already
  // ignores blank secret fields, but being explicit here keeps the
  // audit payload tidy and makes save/load symmetric.
  const opnSavePayload = () => {
    const p: any = {
      enabled: opn.enabled,
      url: opn.url,
      api_key: opn.api_key,
      verify_ssl: opn.verify_ssl,
      ids_enabled: opn.ids_enabled,
      poll_interval_seconds: opn.poll_interval_seconds,
    }
    if (opn.api_secret) p.api_secret = opn.api_secret
    return p
  }

  const fwSavePayload = () => {
    const p: any = {
      enabled: fw.enabled,
      mode: fw.mode,
      msp_domain: fw.msp_domain,
      local_url: fw.local_url,
      verify_ssl: fw.verify_ssl,
      alarms_enabled: fw.alarms_enabled,
      poll_interval_seconds: fw.poll_interval_seconds,
    }
    if (fw.msp_token) p.msp_token = fw.msp_token
    if (fw.local_token) p.local_token = fw.local_token
    return p
  }

  return (
    <TronPanel className="p-4">
      <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider mb-1">
        Gateway Integrations
      </h2>
      <p className="text-xs font-mono text-slate-500 mb-4">
        Optional edge gateways. Each feeds the Devices page (DHCP / device
        inventory) and the Security page (IDS / alarm feed). Leave disabled
        if you don't run one — UniFi alone is enough for a basic setup.
      </p>

      <div className="space-y-3">

        {/* ── OPNsense ────────────────────────────────────────────── */}
        <CredSection
          title="OPNsense Firewall"
          testStatus={opnTest}
          test={() => run(
            async () => {
              const { data } = await client.post('/setup/test-opnsense', {
                url: opn.url,
                api_key: opn.api_key,
                api_secret: opn.api_secret,    // blank → backend falls back to stored
                verify_ssl: opn.verify_ssl,
                ids_enabled: opn.ids_enabled,
              })
              const bits = [data.product, data.version].filter(Boolean).join(' ')
              return { bits }
            },
            opnTest,
            'connected',
          )}
          save={() => run(
            async () => await saveSection('opnsense', opnSavePayload()),
            opnTest,
            'saved',
          )}
        >
          <label className="col-span-2 flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={opn.enabled}
              onChange={(e) => setOpn({ ...opn, enabled: e.target.checked })}
              className="accent-tron-cyan"
            />
            Enable OPNsense polling
          </label>
          <TextField
            label="Base URL"
            value={opn.url}
            onChange={(v) => setOpn({ ...opn, url: v })}
            placeholder="https://10.0.0.1"
          />
          <TextField
            label="Poll interval (seconds)"
            type="number"
            value={String(opn.poll_interval_seconds)}
            onChange={(v) => setOpn({ ...opn, poll_interval_seconds: Number(v) || 60 })}
          />
          <TextField
            label="API key"
            value={opn.api_key}
            onChange={(v) => setOpn({ ...opn, api_key: v })}
            placeholder="System → Access → Users → API keys"
          />
          <TextField
            label="API secret"
            type="password"
            value={opn.api_secret}
            onChange={(v) => setOpn({ ...opn, api_secret: v })}
            placeholder={opnSecretStored ? '(unchanged)' : 'secret half of key pair'}
          />
          <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={opn.verify_ssl}
              onChange={(e) => setOpn({ ...opn, verify_ssl: e.target.checked })}
              className="accent-tron-cyan"
            />
            Verify SSL certificate
          </label>
          <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={opn.ids_enabled}
              onChange={(e) => setOpn({ ...opn, ids_enabled: e.target.checked })}
              className="accent-tron-cyan"
            />
            Pull Suricata IDS alerts
          </label>
          <p className="col-span-2 text-[11px] font-mono text-slate-500 leading-snug">
            Generate a key pair under <span className="text-tron-cyan">System → Access → Users → (your user) → API keys</span>.
            Defaults to self-signed cert — uncheck Verify SSL unless you've installed a real certificate.
          </p>
        </CredSection>

        {/* ── Firewalla ───────────────────────────────────────────── */}
        <CredSection
          title="Firewalla"
          testStatus={fwTest}
          test={() => run(
            async () => {
              const { data } = await client.post('/setup/test-firewalla', {
                mode: fw.mode,
                msp_domain: fw.msp_domain,
                msp_token: fw.msp_token,
                local_url: fw.local_url,
                local_token: fw.local_token,
                verify_ssl: fw.verify_ssl,
              })
              return { count: data.box_count }
            },
            fwTest,
            'connected',
          )}
          save={() => run(
            async () => await saveSection('firewalla', fwSavePayload()),
            fwTest,
            'saved',
          )}
        >
          <label className="col-span-2 flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={fw.enabled}
              onChange={(e) => setFw({ ...fw, enabled: e.target.checked })}
              className="accent-tron-cyan"
            />
            Enable Firewalla polling
          </label>
          <label className="block col-span-2">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Mode</span>
            <div className="mt-0.5 flex gap-2">
              {(['msp', 'local'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setFw({ ...fw, mode: m })}
                  className={`px-3 py-1 text-xs font-mono uppercase tracking-wider rounded border transition-colors ${
                    fw.mode === m
                      ? 'border-tron-cyan/60 text-tron-cyan bg-tron-cyan/10'
                      : 'border-tron-border text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {m === 'msp' ? 'MSP (recommended)' : 'Local (experimental)'}
                </button>
              ))}
            </div>
          </label>

          {fw.mode === 'msp' ? (
            <>
              <TextField
                label="MSP domain"
                value={fw.msp_domain}
                onChange={(v) => setFw({ ...fw, msp_domain: v })}
                placeholder="mycompany.firewalla.net"
              />
              <TextField
                label="Personal access token"
                type="password"
                value={fw.msp_token}
                onChange={(v) => setFw({ ...fw, msp_token: v })}
                placeholder={fwMspTokenStored ? '(unchanged)' : 'Account Settings → Create New Token'}
              />
            </>
          ) : (
            <>
              <TextField
                label="Box URL"
                value={fw.local_url}
                onChange={(v) => setFw({ ...fw, local_url: v })}
                placeholder="http://192.168.1.1:8833"
              />
              <TextField
                label="Fireguard token"
                type="password"
                value={fw.local_token}
                onChange={(v) => setFw({ ...fw, local_token: v })}
                placeholder={fwLocalTokenStored ? '(unchanged)' : 'from box → Settings → API'}
              />
            </>
          )}

          <TextField
            label="Poll interval (seconds)"
            type="number"
            value={String(fw.poll_interval_seconds)}
            onChange={(v) => setFw({ ...fw, poll_interval_seconds: Number(v) || 120 })}
          />
          <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={fw.alarms_enabled}
              onChange={(e) => setFw({ ...fw, alarms_enabled: e.target.checked })}
              className="accent-tron-cyan"
            />
            Pull alarm feed
          </label>
          <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={fw.verify_ssl}
              onChange={(e) => setFw({ ...fw, verify_ssl: e.target.checked })}
              className="accent-tron-cyan"
            />
            Verify SSL certificate
          </label>

          <p className="col-span-2 text-[11px] font-mono text-slate-500 leading-snug">
            {fw.mode === 'msp' ? (
              <>
                Create a Personal Access Token in the MSP portal under{' '}
                <span className="text-tron-cyan">Account Settings → Create New Token</span>.
                Tokens are shown once — paste it here immediately.
              </>
            ) : (
              <>
                <AlertTriangle size={10} className="inline mr-1 text-amber-400" />
                The local box API is not officially documented. Expect degraded
                functionality vs MSP mode — use MSP unless you specifically
                need to avoid the cloud.
              </>
            )}
          </p>
        </CredSection>

      </div>

      <p className="text-xs text-slate-500 mt-3 font-mono">
        Secrets left blank preserve the existing stored value. Changes take effect on the next poll interval — no backend restart required.
      </p>
    </TronPanel>
  )
}


function IntegrationsCard({ settings }: { settings: any }) {
  const qc = useQueryClient()

  // UniFi
  const [unifi, setUnifi] = useState({
    url: settings?.unifi?.url ?? '',
    user: settings?.unifi?.user ?? '',
    password: '',
    site: settings?.unifi?.site ?? 'default',
  })
  const unifiTest = useTestStatus()

  // Elasticsearch
  const [es, setEs] = useState({
    host: settings?.elasticsearch?.host ?? '',
    port: settings?.elasticsearch?.port ?? 9200,
    user: settings?.elasticsearch?.user ?? '',
    password: '',
  })
  const esTest = useTestStatus()

  // OpenVAS
  // Default host matches the schema default (`homelab-openvas` container_name).
  // The service-name alias `openvas` also resolves on `homelab-net`, but only
  // for as long as compose manages the container — our reset flow recreates
  // via the docker SDK, which drops the service-name alias. Using the
  // container name means the host setting works before AND after a reset.
  const [ov, setOv] = useState({
    host: settings?.openvas?.host ?? 'homelab-openvas',
    port: settings?.openvas?.port ?? 9390,
    user: settings?.openvas?.user ?? 'admin',
    // Masked presence flag from the API. The backend returns `"••••••"`
    // when a password is stored and `""` when it isn't — we only need the
    // boolean for UI copy ("No password set yet" vs "Rotate to regenerate").
    // The raw password is never sent to the browser.
    passwordSet: Boolean(settings?.openvas?.password),
  })
  const ovTest = useTestStatus()
  const [resetModalOpen, setResetModalOpen] = useState(false)

  // Re-hydrate local form state once settings finish loading. Without this,
  // the form keeps the `?? 'admin'` defaults and a naive "Save" re-submits
  // `admin` back to the server, clobbering whatever user was actually stored.
  useEffect(() => {
    if (!settings) return
    if (settings.unifi) {
      setUnifi((u) => ({
        ...u,
        url: settings.unifi.url ?? u.url,
        user: settings.unifi.user ?? u.user,
        site: settings.unifi.site ?? u.site,
      }))
    }
    if (settings.elasticsearch) {
      setEs((e) => ({
        ...e,
        host: settings.elasticsearch.host ?? e.host,
        port: settings.elasticsearch.port ?? e.port,
        user: settings.elasticsearch.user ?? e.user,
      }))
    }
    if (settings.openvas) {
      setOv((o) => ({
        ...o,
        host: settings.openvas.host ?? o.host,
        port: settings.openvas.port ?? o.port,
        user: settings.openvas.user ?? o.user,
        passwordSet: Boolean(settings.openvas.password),
      }))
    }
    // UniFi + ES still use the legacy (user-typed) password flow and need
    // blank inputs to preserve "(unchanged)" semantics. OpenVAS no longer
    // has a password field at all — see openvas_autopassword.py.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    settings?.unifi?.url, settings?.unifi?.user, settings?.unifi?.site,
    settings?.elasticsearch?.host, settings?.elasticsearch?.port, settings?.elasticsearch?.user,
    settings?.openvas?.host, settings?.openvas?.port, settings?.openvas?.user,
    settings?.openvas?.password,
  ])

  async function run(fn: () => Promise<any>, t: ReturnType<typeof useTestStatus>, label: string) {
    t.setStatus('testing'); t.setDetail('')
    try {
      const r = await fn()
      t.setStatus('ok'); t.setDetail(label)
      return r
    } catch (e: any) {
      t.setStatus('fail'); t.setDetail(e.message || 'failed')
    }
  }

  const saveSection = async (key: string, body: any) => {
    await client.post('/setup/complete', { [key]: body })
    qc.invalidateQueries({ queryKey: ['settings'] })
  }

  return (
    <TronPanel className="p-4">
      <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider mb-4">Integration Credentials</h2>
      <div className="space-y-3">

        {/* UniFi */}
        <CredSection
          title="UniFi Controller"
          testStatus={unifiTest}
          test={() => run(
            async () => {
              const { data } = await client.post('/setup/test-unifi', unifi)
              return data
            },
            unifiTest,
            'connected',
          )}
          save={() => run(
            async () => await saveSection('unifi', unifi),
            unifiTest,
            'saved',
          )}
        >
          <TextField label="URL" value={unifi.url} onChange={(v) => setUnifi({ ...unifi, url: v })} placeholder="https://192.168.1.1" />
          <TextField label="Site" value={unifi.site} onChange={(v) => setUnifi({ ...unifi, site: v })} />
          <TextField label="User" value={unifi.user} onChange={(v) => setUnifi({ ...unifi, user: v })} />
          <TextField label="Password" type="password" value={unifi.password} onChange={(v) => setUnifi({ ...unifi, password: v })} placeholder="(unchanged)" />
        </CredSection>

        {/* Elasticsearch */}
        <CredSection
          title="Elasticsearch"
          testStatus={esTest}
          test={() => run(
            async () => {
              const { data } = await client.post('/setup/test-elasticsearch', es)
              return data
            },
            esTest,
            'reachable',
          )}
          save={() => run(
            async () => await saveSection('elasticsearch', es),
            esTest,
            'saved',
          )}
        >
          <TextField label="Host" value={es.host} onChange={(v) => setEs({ ...es, host: v })} placeholder="192.168.1.100" />
          <TextField label="Port" type="number" value={String(es.port)} onChange={(v) => setEs({ ...es, port: Number(v) })} />
          <TextField label="User" value={es.user} onChange={(v) => setEs({ ...es, user: v })} />
          <TextField label="Password" type="password" value={es.password} onChange={(v) => setEs({ ...es, password: v })} placeholder="(unchanged)" />
        </CredSection>

        {/* OpenVAS */}
        <CredSection
          title="OpenVAS / Greenbone"
          testStatus={ovTest}
          test={() => run(
            async () => {
              // Test endpoint accepts a blank password and falls back to
              // the stored one — which is what we always want now that
              // the password is platform-managed.
              const { data } = await client.post('/setup/test-openvas', {
                host: ov.host, port: ov.port, user: ov.user, password: '',
              })
              return data
            },
            ovTest,
            'reachable',
          )}
          save={() => run(
            async () => await saveSection('openvas', {
              host: ov.host, port: ov.port, user: ov.user,
            }),
            ovTest,
            'saved',
          )}
        >
          <TextField label="Host" value={ov.host} onChange={(v) => setOv({ ...ov, host: v })} />
          <TextField label="Port" type="number" value={String(ov.port)} onChange={(v) => setOv({ ...ov, port: Number(v) })} />
          <TextField label="User" value={ov.user} onChange={(v) => setOv({ ...ov, user: v })} />
          {/* No password field! The OpenVAS admin password is auto-managed
              by the platform — generated on first setup, stored in config,
              rotated via the button below. The user never needs to see or
              type it: the backend is the only thing that ever talks to
              gvmd. Full rationale in services/openvas_autopassword.py. */}
          <div className="col-span-2 -mt-1 mb-1 p-2 rounded border border-tron-border/40 bg-tron-dark/50 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[11px] font-mono text-tron-cyan/80 leading-snug">
                <KeyRound size={10} className="inline mr-1" />
                Admin password is auto-managed
              </p>
              <p className="text-[10px] font-mono text-slate-500 leading-snug mt-0.5">
                {ov.passwordSet
                  ? 'A secure random password is stored. Rotate to generate a fresh one (wipes NVT cache + scan history, ~10 min warmup).'
                  : 'No password set yet. Click Rotate to generate one and initialise the container.'}
              </p>
            </div>
            <GlowButton size="sm" variant="ghost" onClick={() => setResetModalOpen(true)}>
              <KeyRound size={12} className="mr-1" /> Rotate
            </GlowButton>
          </div>
        </CredSection>
      </div>
      <p className="text-xs text-slate-500 mt-3 font-mono">
        Admin credentials for each service. Passwords left blank preserve the existing value.
      </p>
      <ResetOpenVASModal
        open={resetModalOpen}
        currentUser={ov.user || 'admin'}
        onClose={() => setResetModalOpen(false)}
      />
    </TronPanel>
  )
}

// =============================================================================
// AI Analysis — configure the daily Ollama-backed report
// =============================================================================

function AIAnalysisCard({ settings }: { settings: any }) {
  const qc = useQueryClient()
  const current = settings?.ollama ?? {}

  const [form, setForm] = useState({
    enabled: current.enabled ?? false,
    host: current.host ?? '',
    port: current.port ?? 11434,
    model: current.model ?? 'gemma3:4b',
    api_key: '',
    daily_schedule_hour_utc: current.daily_schedule_hour_utc ?? 6,
  })

  useEffect(() => {
    if (!settings?.ollama) return
    setForm((f) => ({
      ...f,
      enabled: settings.ollama.enabled,
      host: settings.ollama.host,
      port: settings.ollama.port,
      model: settings.ollama.model,
      daily_schedule_hour_utc: settings.ollama.daily_schedule_hour_utc,
    }))
    // We intentionally list the primitive fields instead of the parent
    // `settings.ollama` object: the query is refetched on a 30s interval
    // and the object reference churns each refetch even when nothing
    // inside it changed. Listing the fields keeps the reseed as a
    // genuine user-edit counter rather than a poll-induced reset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings?.ollama?.enabled, settings?.ollama?.host, settings?.ollama?.port,
      settings?.ollama?.model, settings?.ollama?.daily_schedule_hour_utc])

  const testState = useTestStatus()

  const save = useMutation({
    mutationFn: async () => client.post('/setup/complete', { ollama: form }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })

  const doTest = async () => {
    testState.setStatus('testing'); testState.setDetail('')
    try {
      const { data } = await client.post('/setup/test-ollama', {
        host: form.host, port: form.port, model: form.model, api_key: form.api_key,
      })
      const tag = data.model_present ? `ok · ${data.models?.length ?? 0} models`
                                     : `reachable · model '${form.model}' not loaded`
      testState.setStatus(data.model_present ? 'ok' : 'fail'); testState.setDetail(tag)
    } catch (e: any) {
      testState.setStatus('fail')
      testState.setDetail(e?.response?.data?.detail || e?.message || 'failed')
    }
  }

  return (
    <TronPanel className="p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider flex items-center gap-2">
          <Brain size={14} /> AI Analysis (Ollama)
        </h2>
        <StatusPill status={testState.status} detail={testState.detail} />
      </div>

      <p className="text-xs font-mono text-slate-500 mb-3">
        Daily brief generated by a local Ollama model from 24h of Elasticsearch telemetry.
        Enable to surface the Analysis page in the sidebar and activate the scheduled job.
      </p>

      <div className="grid grid-cols-3 gap-3">
        <label className="block col-span-2">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Host</span>
          <input
            type="text"
            value={form.host}
            placeholder="192.168.1.100 or http://host:port"
            onChange={(e) => setForm({ ...form, host: e.target.value })}
            className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Port</span>
          <input
            type="number"
            value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
            className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block col-span-2">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Model</span>
          <input
            type="text"
            value={form.model}
            placeholder="gemma3:4b"
            onChange={(e) => setForm({ ...form, model: e.target.value })}
            className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Daily hour (UTC)</span>
          <input
            type="number"
            min={0}
            max={23}
            value={form.daily_schedule_hour_utc}
            onChange={(e) => setForm({ ...form, daily_schedule_hour_utc: Number(e.target.value) })}
            className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
        <label className="block col-span-3">
          <span className="text-[10px] font-mono text-slate-500 uppercase">API key (OpenWebUI only)</span>
          <input
            type="password"
            value={form.api_key}
            placeholder="(unchanged — blank preserves existing)"
            onChange={(e) => setForm({ ...form, api_key: e.target.value })}
            className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
          />
        </label>
      </div>

      <div className="flex items-center gap-4 mt-3">
        <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="accent-tron-cyan"
          />
          Enabled
        </label>
        <div className="flex-1" />
        <GlowButton size="sm" variant="ghost" onClick={doTest}>
          <Zap size={12} className="mr-1" /> Test
        </GlowButton>
        <GlowButton size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
          <Save size={12} className="mr-1" /> Save
        </GlowButton>
      </div>

      <p className="text-xs text-slate-600 mt-3 font-mono">
        After enabling or changing the schedule hour, restart the backend for the cron job to pick up the new schedule.
      </p>
    </TronPanel>
  )
}

// =============================================================================
// Scan Credentials — per-target SSH/SMB creds for OpenVAS credentialed scans
// Backed by /api/vulns/credentials.
// =============================================================================

interface ScanCred {
  id: string
  target_ip: string
  username: string
  auth_type?: 'password' | 'key'
  note?: string | null
}

type TestResultRow = { ip: string; status: string; detail: string; ok: boolean }
type TestSummary = {
  host_count: number
  ok_count: number
  fail_count: number
  all_ok: boolean
  results: TestResultRow[]
}

function ScanCredentialsCard() {
  const qc = useQueryClient()
  const { data: creds = [] } = useQuery<ScanCred[]>({
    queryKey: ['scan-credentials'],
    queryFn: async () => (await client.get('/vulns/credentials')).data,
  })

  const [draft, setDraft] = useState({
    target_ip: '',
    username: '',
    auth_type: 'password' as 'password' | 'key',
    password: '',
    private_key: '',
    key_passphrase: '',
    note: '',
  })

  // Persistent test badge — stays visible after Save so the user can see at a
  // glance whether the credentials they just stored actually worked. Reset
  // only when the draft inputs change (so editing invalidates stale state).
  const [testBadge, setTestBadge] = useState<
    | { kind: 'ok'; summary: TestSummary }
    | { kind: 'fail'; summary: TestSummary }
    | { kind: 'error'; detail: string }
    | { kind: 'testing' }
    | null
  >(null)

  // Invalidate the stale badge when any draft field changes. Using a
  // serialised draft signature avoids rebuilding the deps array row-by-row.
  const draftSig = JSON.stringify(draft)
  useEffect(() => {
    setTestBadge(null)
  }, [draftSig])

  const runTest = async () => {
    setTestBadge({ kind: 'testing' })
    try {
      const payload = {
        target_ip: draft.target_ip,
        username: draft.username,
        auth_type: draft.auth_type,
        password: draft.auth_type === 'password' ? draft.password : '',
        private_key: draft.auth_type === 'key' ? draft.private_key : '',
        key_passphrase: draft.auth_type === 'key' ? draft.key_passphrase : '',
      }
      const { data } = await client.post<TestSummary>('/vulns/credentials/test', payload)
      setTestBadge({ kind: data.all_ok ? 'ok' : 'fail', summary: data })
    } catch (e: any) {
      setTestBadge({ kind: 'error', detail: e?.response?.data?.detail || e?.message || 'failed' })
    }
  }

  const add = useMutation({
    mutationFn: async () => client.post('/vulns/credentials', {
      target_ip: draft.target_ip,
      username: draft.username,
      auth_type: draft.auth_type,
      password: draft.auth_type === 'password' ? draft.password : '',
      private_key: draft.auth_type === 'key' ? draft.private_key : '',
      key_passphrase: draft.auth_type === 'key' ? draft.key_passphrase : '',
      note: draft.note,
    }),
    onSuccess: () => {
      // Keep testBadge so the confirmed result stays on screen after save.
      setDraft({ target_ip: '', username: '', auth_type: 'password', password: '', private_key: '', key_passphrase: '', note: '' })
      qc.invalidateQueries({ queryKey: ['scan-credentials'] })
    },
  })

  const del = useMutation({
    mutationFn: async (id: string) => client.delete(`/vulns/credentials/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-credentials'] }),
  })

  return (
    <TronPanel className="p-4">
      <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider mb-2">Scan Credentials</h2>
      <p className="text-xs font-mono text-slate-500 mb-3">
        Per-target SSH credentials used by OpenVAS for credentialed scans.
        Target accepts a single IP, a comma list (<span className="text-tron-cyan">192.168.1.10, .11</span>),
        a last-octet range (<span className="text-tron-cyan">192.168.1.5-10</span>),
        a CIDR (<span className="text-tron-cyan">192.168.1.16/29</span>),
        or <span className="text-tron-cyan">*</span> for a wildcard default.
      </p>

      {/* List */}
      <div className="space-y-1 mb-3">
        {creds.length === 0 && (
          <div className="text-xs font-mono text-slate-600 italic">No credentials stored.</div>
        )}
        {creds.map((c) => (
          <div key={c.id}
            className="flex items-center justify-between py-1.5 px-2 border border-tron-border/30 rounded text-xs font-mono"
          >
            <div className="flex items-center gap-3">
              <span className="text-tron-cyan w-40">{c.target_ip}</span>
              <span className="text-slate-300">{c.username}</span>
              <span className="text-[10px] uppercase tracking-wider text-slate-500 px-1.5 py-0.5 rounded bg-slate-800/60">
                {c.auth_type === 'key' ? 'key' : 'password'}
              </span>
              {c.note && <span className="text-slate-600 italic">{c.note}</span>}
            </div>
            <button
              onClick={() => del.mutate(c.id)}
              className="text-slate-500 hover:text-status-offline transition-colors"
              title="Delete credential"
            >
              <Trash2 size={12} />
            </button>
          </div>
        ))}
      </div>

      {/* Add form */}
      <div className="border-t border-tron-border/30 pt-3 space-y-2">
        <div className="grid grid-cols-4 gap-2">
          <TextField label="Target" value={draft.target_ip}
            onChange={(v) => setDraft({ ...draft, target_ip: v })}
            placeholder="192.168.1.50 or 192.168.1.5-10 or *" />
          <TextField label="Username" value={draft.username}
            onChange={(v) => setDraft({ ...draft, username: v })} />
          <label className="block">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Auth</span>
            <select
              value={draft.auth_type}
              onChange={(e) => setDraft({ ...draft, auth_type: e.target.value as 'password' | 'key' })}
              className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-tron-cyan/50"
            >
              <option value="password">Password</option>
              <option value="key">SSH Key</option>
            </select>
          </label>
          <TextField label="Note" value={draft.note}
            onChange={(v) => setDraft({ ...draft, note: v })}
            placeholder="optional" />
        </div>

        {/* Auth-specific inputs */}
        {draft.auth_type === 'password' ? (
          <div className="grid grid-cols-2 gap-2">
            <TextField label="Password" type="password" value={draft.password}
              onChange={(v) => setDraft({ ...draft, password: v })} />
          </div>
        ) : (
          <div className="space-y-2">
            <label className="block">
              <span className="text-[10px] font-mono text-slate-500 uppercase">Private Key (PEM)</span>
              <textarea
                value={draft.private_key}
                onChange={(e) => setDraft({ ...draft, private_key: e.target.value })}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                rows={5}
                className="mt-0.5 w-full px-2 py-1 bg-tron-dark border border-tron-border rounded font-mono text-[11px] text-slate-200 focus:outline-none focus:border-tron-cyan/50 resize-y"
              />
            </label>
            <div className="grid grid-cols-2 gap-2">
              <TextField label="Key Passphrase (optional)" type="password"
                value={draft.key_passphrase}
                onChange={(v) => setDraft({ ...draft, key_passphrase: v })} />
            </div>
          </div>
        )}

        <div className="flex items-center gap-2 pt-1">
          <GlowButton
            size="sm"
            variant="ghost"
            onClick={runTest}
            disabled={
              !draft.target_ip || !draft.username ||
              (draft.auth_type === 'password' && !draft.password) ||
              (draft.auth_type === 'key' && !draft.private_key) ||
              testBadge?.kind === 'testing'
            }
          >
            <Zap size={12} className="mr-1" /> Test
          </GlowButton>

          <GlowButton
            size="sm"
            onClick={() => add.mutate()}
            disabled={add.isPending}
          >
            <Plus size={12} className="mr-1" />
            Save Credential
          </GlowButton>

          {/* Persistent badge */}
          <div className="flex-1" />
          <CredTestBadge state={testBadge} />
        </div>
      </div>
    </TronPanel>
  )
}

/** Persistent green/red badge next to the Test+Save row. Mirrors the
 *  per-integration StatusPill style but carries extra context: "N/M hosts" on
 *  multi-host tests, and "check logs" on partial failure (matches the wording
 *  the user specified). */
function CredTestBadge({
  state,
}: {
  state:
    | { kind: 'ok'; summary: TestSummary }
    | { kind: 'fail'; summary: TestSummary }
    | { kind: 'error'; detail: string }
    | { kind: 'testing' }
    | null
}) {
  if (!state) return null
  if (state.kind === 'testing') {
    return (
      <span className="flex items-center gap-1 text-xs font-mono text-slate-400">
        <Zap size={12} className="animate-pulse" /> testing…
      </span>
    )
  }
  if (state.kind === 'error') {
    return (
      <span className="flex items-center gap-1 text-xs font-mono text-status-offline px-2 py-0.5 rounded bg-red-950/40 border border-red-900/50">
        <X size={12} /> {state.detail}
      </span>
    )
  }
  if (state.kind === 'ok') {
    const { host_count } = state.summary
    return (
      <span className="flex items-center gap-1 text-xs font-mono text-status-online px-2 py-0.5 rounded bg-green-950/30 border border-green-900/50">
        <Check size={12} />
        {host_count > 1 ? `OK · ${host_count}/${host_count} hosts` : 'OK'}
      </span>
    )
  }
  // fail
  const { ok_count, host_count } = state.summary
  return (
    <span className="flex items-center gap-1 text-xs font-mono text-status-offline px-2 py-0.5 rounded bg-red-950/40 border border-red-900/50"
      title="See the Audit Log for per-host details"
    >
      <X size={12} />
      {host_count > 1
        ? `${ok_count}/${host_count} OK — at least one credential failed, check logs`
        : 'at least one credential failed, check logs'}
    </span>
  )
}

// =============================================================================
// Main page
// =============================================================================

export function SettingsPage() {
  const { data: settings } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => (await client.get('/settings')).data,
  })

  const { status: schedStatus, jobMap, triggerJob, isTriggering } = useScanSchedule()
  const qc = useQueryClient()

  const togglePause = useMutation({
    mutationFn: async ({ id, paused }: { id: string; paused: boolean }) =>
      client.post(`/scheduler/${paused ? 'resume' : 'pause'}/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scheduler-status'] }),
  })

  const scheduler = settings?.scheduler

  return (
    <div className="h-full overflow-auto p-4 space-y-4">

      {/* ── Scheduler Status ─────────────────────────────────────── */}
      <TronPanel className="p-4">
        <div className="flex items-center gap-2 mb-4">
          <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider">Scheduler</h2>
          <span className={`text-xs font-mono px-2 py-0.5 rounded-full ${
            schedStatus?.running
              ? 'bg-status-online/10 text-status-online'
              : 'bg-slate-700 text-slate-400'
          }`}>
            {schedStatus?.mock ? 'mock' : schedStatus?.running ? 'running' : 'stopped'}
          </span>
        </div>

        <div className="space-y-3">
          {SCHEDULER_JOBS.map(({ id, label }) => {
            const info = jobMap[id]
            const paused = info?.paused === true
            return (
              <div key={id} className="flex items-center justify-between py-2 border-b border-tron-border/30 last:border-0">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-mono text-slate-200">{label}</p>
                    {paused && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 uppercase tracking-wider">
                        paused
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-mono text-slate-500 flex items-center gap-1 mt-0.5">
                    <Clock size={10} />
                    Next: {paused ? 'paused' : fmtNextRun(info?.next_run)}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <GlowButton
                    size="sm"
                    variant="ghost"
                    onClick={() => togglePause.mutate({ id, paused })}
                    disabled={togglePause.isPending || schedStatus?.mock}
                    title={paused ? 'Resume scheduled runs' : 'Pause scheduled runs (manual Run Now still works)'}
                  >
                    {paused ? <Play size={12} className="mr-1" /> : <Pause size={12} className="mr-1" />}
                    {paused ? 'Resume' : 'Pause'}
                  </GlowButton>
                  <GlowButton size="sm" variant="ghost" onClick={() => triggerJob(id)} disabled={isTriggering}>
                    <Play size={12} className="mr-1" />
                    Run Now
                  </GlowButton>
                </div>
              </div>
            )
          })}
        </div>
        <p className="text-xs text-slate-600 mt-3 font-mono">
          Pausing stops a job from firing on its interval. Manual "Run Now" still works. Pauses reset on backend restart.
        </p>
      </TronPanel>

      {/* ── Scan Intervals ───────────────────────────────────────── */}
      <ScanIntervalsCard scheduler={scheduler} />

      {/* ── Integration Credentials (UniFi / ES / OpenVAS) ───────── */}
      <IntegrationsCard settings={settings} />

      {/* ── Gateway Integrations (OPNsense / Firewalla) ──────────── */}
      <GatewayIntegrationsCard settings={settings} />

      {/* ── AI Analysis (Ollama) ─────────────────────────────────── */}
      <AIAnalysisCard settings={settings} />

      {/* ── Scan Credentials (per-target SSH/SMB) ────────────────── */}
      <ScanCredentialsCard />

      {/* ── Network Proxy (compose-time, read-only here) ─────────── */}
      <TronPanel className="p-4">
        <h2 className="text-tron-cyan font-mono text-sm uppercase tracking-wider mb-4">Network Proxy</h2>
        <div className="space-y-2 text-sm font-mono text-slate-400">
          <div>Mode: <span className="text-slate-200">{settings?.proxy?.mode ?? '—'}</span></div>
          <div>Host: <span className="text-slate-200">{settings?.proxy?.external_host ?? '—'}</span></div>
          <div>Certs: <span className="text-slate-200">{settings?.proxy?.cert_type ?? '—'}</span></div>
        </div>
        <p className="text-xs text-slate-600 mt-3">Re-run deploy.sh to change proxy/cert configuration.</p>
      </TronPanel>
    </div>
  )
}

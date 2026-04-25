import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, XCircle, Loader2, ChevronRight, ChevronLeft, Wifi, Database, Shield, Zap } from 'lucide-react'
import client from '../api/client'

// ── Types ─────────────────────────────────────────────────────────────────────

interface StepState {
  network: {
    external_host: string
    domain_mode: 'ip' | 'domain'
    cert_type: 'none' | 'selfsigned' | 'letsencrypt'
    letsencrypt_email: string
  }
  elasticsearch: { host: string; port: number; user: string; password: string }
  unifi: { url: string; user: string; password: string; site: string }
  services: { openvas_user: string; openvas_pass: string } // openvas_pass retained for legacy state shape; platform auto-manages
  claude: { enabled: boolean }
}

type TestStatus = 'idle' | 'testing' | 'ok' | 'error'

// ── Step definitions ──────────────────────────────────────────────────────────

const STEPS = [
  { id: 'network',       label: 'Network',       icon: Wifi },
  { id: 'elasticsearch', label: 'Elasticsearch', icon: Database },
  { id: 'unifi',         label: 'UniFi',         icon: Wifi },
  { id: 'services',      label: 'Services',      icon: Shield },
  { id: 'review',        label: 'Review',        icon: CheckCircle },
]

// ── Field helpers ─────────────────────────────────────────────────────────────

function Field({
  label, value, onChange, type = 'text', placeholder = '', hint = '',
}: {
  label: string; value: string; onChange: (v: string) => void
  type?: string; placeholder?: string; hint?: string
}) {
  return (
    <label className="block">
      <span className="text-xs font-mono text-slate-400">{label}</span>
      {hint && <span className="ml-2 text-xs font-mono text-slate-600">{hint}</span>}
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete="off"
        className="mt-1 block w-full px-3 py-2 bg-tron-dark border border-tron-border rounded font-mono
                   text-sm text-slate-200 placeholder:text-slate-700
                   focus:outline-none focus:border-tron-cyan/50 focus:shadow-tron-sm transition-colors"
      />
    </label>
  )
}

function TestButton({
  status, onTest,
}: { status: TestStatus; onTest: () => void }) {
  return (
    <div className="flex items-center gap-3 mt-2">
      <button
        onClick={onTest}
        disabled={status === 'testing'}
        className="inline-flex items-center gap-2 px-4 py-1.5 font-mono text-xs border border-tron-cyan
                   text-tron-cyan rounded hover:bg-tron-cyan/10 transition-colors
                   disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {status === 'testing' ? <Loader2 size={12} className="animate-spin" /> : <Zap size={12} />}
        Test Connection
      </button>
      {status === 'ok' && (
        <span className="flex items-center gap-1 text-xs font-mono text-status-online">
          <CheckCircle size={12} /> Connected
        </span>
      )}
      {status === 'error' && (
        <span className="flex items-center gap-1 text-xs font-mono text-status-offline">
          <XCircle size={12} /> Failed — check credentials
        </span>
      )}
    </div>
  )
}

// ── Progress bar ──────────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: number; total: number }) {
  return (
    <div className="flex items-center gap-2 mb-8">
      {STEPS.map((s, i) => {
        const Icon = s.icon
        const done = i < current
        const active = i === current
        return (
          <div key={s.id} className="flex items-center gap-2">
            <div className={`flex items-center justify-center w-8 h-8 rounded-full border font-mono text-xs transition-all duration-300
              ${done ? 'border-status-online bg-status-online/10 text-status-online'
              : active ? 'border-tron-cyan bg-tron-cyan/10 text-tron-cyan shadow-tron-sm'
              : 'border-tron-border text-slate-600'}`}>
              {done ? <CheckCircle size={14} /> : <Icon size={14} />}
            </div>
            <span className={`text-xs font-mono hidden sm:block transition-colors
              ${active ? 'text-tron-cyan' : done ? 'text-status-online' : 'text-slate-600'}`}>
              {s.label}
            </span>
            {i < STEPS.length - 1 && (
              <div className={`w-8 h-px transition-colors ${done ? 'bg-status-online/40' : 'bg-tron-border'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function SetupPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState(0)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  const [state, setState] = useState<StepState>({
    network: {
      external_host: window.location.hostname,
      domain_mode: 'ip',
      cert_type: 'none',
      letsencrypt_email: '',
    },
    elasticsearch: { host: '', port: 9200, user: '', password: '' },
    unifi: { url: 'https://192.168.1.1', user: 'admin', password: '', site: 'default' },
    services: { openvas_user: 'admin', openvas_pass: '' },
    claude: { enabled: false },
  })

  function patch<K extends keyof StepState>(section: K, updates: Partial<StepState[K]>) {
    setState((s) => ({ ...s, [section]: { ...s[section], ...updates } }))
  }

  const [esTest, setEsTest] = useState<TestStatus>('idle')
  const [unifiTest, setUnifiTest] = useState<TestStatus>('idle')
  const [unifiSites, setUnifiSites] = useState<Array<{ id: string; display_name: string }>>([])

  async function testES() {
    setEsTest('testing')
    try {
      await client.post('/setup/test-elasticsearch', {
        host: state.elasticsearch.host,
        port: state.elasticsearch.port,
        user: state.elasticsearch.user,
        password: state.elasticsearch.password,
      })
      setEsTest('ok')
    } catch { setEsTest('error') }
  }

  async function testUniFi() {
    setUnifiTest('testing')
    try {
      const res = await client.post('/setup/test-unifi', {
        url: state.unifi.url,
        user: state.unifi.user,
        password: state.unifi.password,
      })
      const sites: Array<{ id: string; display_name: string }> = res.data?.sites ?? []
      setUnifiSites(sites)
      // If the current site value doesn't exist in the returned list, auto-select
      // the first site (usually 'default'). This fixes configs where someone
      // typed the display name instead of the internal site ID.
      if (sites.length > 0 && !sites.some((s) => s.id === state.unifi.site)) {
        patch('unifi', { site: sites[0].id })
      }
      setUnifiTest('ok')
    } catch { setUnifiTest('error') }
  }

  async function handleComplete() {
    setSaving(true)
    setSaveError('')
    try {
      await client.post('/setup/complete', {
        proxy: {
          mode: state.network.domain_mode,
          external_host: state.network.external_host,
          cert_type: state.network.cert_type,
          letsencrypt_email: state.network.letsencrypt_email,
        },
        elasticsearch: {
          host: state.elasticsearch.host,
          port: state.elasticsearch.port,
          user: state.elasticsearch.user,
          password: state.elasticsearch.password,
        },
        unifi: {
          url: state.unifi.url,
          user: state.unifi.user,
          password: state.unifi.password,
          site: state.unifi.site,
        },
        openvas: {
          // No password — the platform auto-generates one and runs the
          // reset flow as soon as /setup/complete returns. See
          // backend/services/openvas_autopassword.py.
          user: state.services.openvas_user,
        },
        claude: { enabled: state.claude.enabled },
      })
      navigate('/network')
    } catch (e: any) {
      setSaveError(e.message || 'Save failed')
      setSaving(false)
    }
  }

  // ── Step content ────────────────────────────────────────────────────────────

  const n = state.network
  const es = state.elasticsearch
  const uf = state.unifi
  const svc = state.services

  const stepContent = [
    // Step 0 — Network
    <div key="network" className="space-y-4">
      <p className="text-xs font-mono text-slate-500 mb-4">
        How is this server accessed from your browser?
      </p>
      <Field
        label="Server IP or Hostname"
        value={n.external_host}
        onChange={(v) => patch('network', { external_host: v })}
        placeholder="192.168.1.10"
      />
      <div>
        <span className="text-xs font-mono text-slate-400">Access Mode</span>
        <div className="mt-2 flex gap-3">
          {(['ip', 'domain'] as const).map((m) => (
            <button key={m}
              onClick={() => patch('network', { domain_mode: m })}
              className={`px-4 py-2 text-xs font-mono border rounded transition-colors
                ${n.domain_mode === m
                  ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                  : 'border-tron-border text-slate-500 hover:border-tron-cyan/40'}`}>
              {m === 'ip' ? 'Raw IP' : 'Domain Name'}
            </button>
          ))}
        </div>
      </div>
      <div>
        <span className="text-xs font-mono text-slate-400">TLS / Certificates</span>
        <div className="mt-2 flex gap-3 flex-wrap">
          {([
            ['none', 'HTTP only'],
            ['selfsigned', 'Self-signed'],
            ['letsencrypt', "Let's Encrypt"],
          ] as const).map(([val, label]) => (
            <button key={val}
              onClick={() => patch('network', { cert_type: val })}
              className={`px-4 py-2 text-xs font-mono border rounded transition-colors
                ${n.cert_type === val
                  ? 'border-tron-cyan text-tron-cyan bg-tron-cyan/10'
                  : 'border-tron-border text-slate-500 hover:border-tron-cyan/40'}`}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {n.cert_type === 'letsencrypt' && (
        <Field
          label="Let's Encrypt Email"
          value={n.letsencrypt_email}
          onChange={(v) => patch('network', { letsencrypt_email: v })}
          placeholder="admin@example.com"
          type="email"
        />
      )}
    </div>,

    // Step 1 — Elasticsearch
    <div key="es" className="space-y-4">
      <p className="text-xs font-mono text-slate-500 mb-4">
        Your existing Elasticsearch instance for device history and scan data. Leave host blank to skip.
      </p>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <Field label="Host / IP" value={es.host} onChange={(v) => patch('elasticsearch', { host: v })} placeholder="192.168.1.x" />
        </div>
        <Field label="Port" value={String(es.port)} onChange={(v) => patch('elasticsearch', { port: Number(v) })} type="number" placeholder="9200" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username" value={es.user} onChange={(v) => patch('elasticsearch', { user: v })} hint="(optional)" />
        <Field label="Password" value={es.password} onChange={(v) => patch('elasticsearch', { password: v })} type="password" hint="(optional)" />
      </div>
      {es.host && <TestButton status={esTest} onTest={testES} />}
    </div>,

    // Step 2 — UniFi
    <div key="unifi" className="space-y-4">
      <p className="text-xs font-mono text-slate-500 mb-4">
        Connect to your UDM Pro for real topology data, switch/AP/client visibility.
      </p>
      <Field label="UDM Pro URL" value={uf.url} onChange={(v) => patch('unifi', { url: v })} placeholder="https://192.168.1.1" />
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username" value={uf.user} onChange={(v) => patch('unifi', { user: v })} />
        <Field label="Password" value={uf.password} onChange={(v) => patch('unifi', { password: v })} type="password" />
      </div>
      {unifiSites.length > 0 ? (
        <label className="block">
          <span className="text-xs font-mono text-slate-400">Site</span>
          <span className="ml-2 text-xs font-mono text-slate-600">
            (internal ID — display name shown in parens)
          </span>
          <select
            value={uf.site}
            onChange={(e) => patch('unifi', { site: e.target.value })}
            className="mt-1 block w-full px-3 py-2 bg-tron-dark border border-tron-border rounded font-mono
                       text-sm text-slate-200
                       focus:outline-none focus:border-tron-cyan/50 focus:shadow-tron-sm transition-colors"
          >
            {unifiSites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id}
                {s.display_name && s.display_name !== s.id ? ` (${s.display_name})` : ''}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <Field
          label="Site"
          value={uf.site}
          onChange={(v) => patch('unifi', { site: v })}
          hint="(usually 'default' — click Test to load real sites)"
        />
      )}
      <TestButton status={unifiTest} onTest={testUniFi} />
    </div>,

    // Step 3 — Services (OpenVAS + Claude)
    <div key="services" className="space-y-6">
      <div className="space-y-3">
        <h3 className="text-xs font-mono text-tron-cyan uppercase tracking-wider">OpenVAS / Greenbone</h3>
        <p className="text-xs font-mono text-slate-500 leading-relaxed">
          Vulnerability scanner running in Docker. The admin password is
          auto-generated and managed by the platform — you never need to
          type, remember, or see it. The container is initialised
          automatically after setup completes (5–10 min NVT warmup).
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Admin Username" value={svc.openvas_user} onChange={(v) => patch('services', { openvas_user: v })} />
        </div>
      </div>

      <div className="space-y-3 pt-4 border-t border-tron-border/30">
        <h3 className="text-xs font-mono text-tron-cyan uppercase tracking-wider">Claude AI Integration</h3>
        <p className="text-xs font-mono text-slate-500">
          Enables automatic analysis of unknown devices and integration suggestions.
        </p>
        <div className="flex items-center gap-3">
          <button
            onClick={() => patch('claude', { enabled: !state.claude.enabled })}
            className={`relative w-10 h-5 rounded-full border transition-all ${
              state.claude.enabled ? 'border-tron-cyan bg-tron-cyan/20' : 'border-tron-border bg-tron-dark'
            }`}
          >
            <span className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${
              state.claude.enabled ? 'left-5 bg-tron-cyan' : 'left-0.5 bg-slate-600'
            }`} />
          </button>
          <span className={`text-xs font-mono ${state.claude.enabled ? 'text-tron-cyan' : 'text-slate-500'}`}>
            {state.claude.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </div>
    </div>,

    // Step 4 — Review
    <div key="review" className="space-y-3">
      <p className="text-xs font-mono text-slate-500 mb-4">Review your configuration before saving.</p>
      {[
        {
          section: 'Network', rows: [
            ['Host', n.external_host],
            ['Mode', n.domain_mode],
            ['TLS', n.cert_type],
          ],
        },
        {
          section: 'Elasticsearch', rows: [
            ['Host', es.host || '—'],
            ['Port', String(es.port)],
            ['Auth', es.user ? es.user : 'none'],
          ],
        },
        {
          section: 'UniFi', rows: [
            ['URL', uf.url],
            ['User', uf.user],
            ['Site', uf.site],
            ['Credentials', uf.password ? '••••••' : '—'],
          ],
        },
        {
          section: 'Services', rows: [
            ['OpenVAS user', svc.openvas_user],
            ['OpenVAS pass', 'auto-managed'],
            ['Claude AI', state.claude.enabled ? 'enabled' : 'disabled'],
          ],
        },
      ].map(({ section, rows }) => (
        <div key={section} className="rounded border border-tron-border/40 overflow-hidden">
          <div className="px-3 py-1.5 bg-tron-panel border-b border-tron-border/40">
            <span className="text-xs font-mono text-tron-cyan uppercase tracking-wider">{section}</span>
          </div>
          <div className="divide-y divide-tron-border/20">
            {rows.map(([k, v]) => (
              <div key={k} className="flex justify-between px-3 py-1.5">
                <span className="text-xs font-mono text-slate-500">{k}</span>
                <span className="text-xs font-mono text-slate-300">{v}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
      {saveError && (
        <p className="text-xs font-mono text-status-offline mt-2 flex items-center gap-1">
          <XCircle size={12} /> {saveError}
        </p>
      )}
    </div>,
  ]

  return (
    <div className="min-h-screen bg-tron-dark tron-grid-bg scanline-overlay flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl"
      >
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-2xl font-mono font-bold text-tron-cyan tracking-widest uppercase">
            Homelab Dashboard
          </h1>
          <p className="text-xs font-mono text-slate-500 mt-1 tracking-wider">First-run configuration</p>
        </div>

        <div className="bg-tron-panel border border-tron-border rounded-lg p-6 shadow-tron-md">
          <StepIndicator current={step} total={STEPS.length} />

          {/* Step title */}
          <h2 className="text-sm font-mono text-slate-200 uppercase tracking-wider mb-5">
            {STEPS[step].label}
          </h2>

          {/* Step content with slide animation */}
          <AnimatePresence mode="wait">
            <motion.div
              key={step}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.18 }}
            >
              {stepContent[step]}
            </motion.div>
          </AnimatePresence>

          {/* Navigation */}
          <div className="flex justify-between mt-8 pt-4 border-t border-tron-border/30">
            <button
              onClick={() => setStep((s) => s - 1)}
              disabled={step === 0}
              className="inline-flex items-center gap-1 px-4 py-2 text-xs font-mono border border-tron-border
                         text-slate-400 rounded hover:border-tron-cyan/50 hover:text-tron-cyan transition-colors
                         disabled:opacity-0 disabled:pointer-events-none"
            >
              <ChevronLeft size={14} /> Back
            </button>

            {step < STEPS.length - 1 ? (
              <button
                onClick={() => setStep((s) => s + 1)}
                className="inline-flex items-center gap-1 px-5 py-2 text-xs font-mono border border-tron-cyan
                           text-tron-cyan rounded hover:bg-tron-cyan/10 hover:shadow-tron-sm transition-all"
              >
                Next <ChevronRight size={14} />
              </button>
            ) : (
              <button
                onClick={handleComplete}
                disabled={saving}
                className="inline-flex items-center gap-2 px-6 py-2 text-xs font-mono border border-status-online
                           text-status-online rounded hover:bg-status-online/10 transition-all
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle size={13} />}
                {saving ? 'Saving…' : 'Save & Launch'}
              </button>
            )}
          </div>
        </div>

        <p className="text-center text-xs font-mono text-slate-700 mt-4">
          Settings can be updated later from the Settings page.
        </p>
      </motion.div>
    </div>
  )
}

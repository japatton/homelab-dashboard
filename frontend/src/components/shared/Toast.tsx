import { createContext, useCallback, useContext, useState } from 'react'
import type { ReactNode } from 'react'
import { CheckCircle2, XCircle, Info, AlertTriangle, X } from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'

// Minimal toast system. Not a react-query wrapper, not a generic notification
// bus — just a lightweight way to acknowledge fire-and-forget mutations
// ("Scan queued", "Rotation started", "Analysis triggered") that today
// happen silently. Rendered in a fixed portal at top-right.
//
// Kept in-tree (rather than react-hot-toast) because we already have
// framer-motion and lucide, and the whole file is <120 lines.

type ToastKind = 'ok' | 'error' | 'info' | 'warn'

interface Toast {
  id: number
  kind: ToastKind
  title: string
  message?: string
  // ms to auto-dismiss; 0 = sticky, user must close
  duration: number
}

interface ToastAPI {
  ok: (title: string, message?: string) => void
  error: (title: string, message?: string) => void
  info: (title: string, message?: string) => void
  warn: (title: string, message?: string) => void
}

const Ctx = createContext<ToastAPI | null>(null)

// `useToast` is co-located with `ToastProvider` because the two are a
// single API surface. The react-refresh linter prefers one component
// per file; in this case the coupling wins over the hot-reload ergonomic.
// eslint-disable-next-line react-refresh/only-export-components
export function useToast(): ToastAPI {
  const ctx = useContext(Ctx)
  if (!ctx) {
    // Safe fallback — no-ops rather than crashing an unwrapped tree.
    // Useful during tests / when the provider hasn't wrapped yet.
    return {
      ok: () => {}, error: () => {}, info: () => {}, warn: () => {},
    }
  }
  return ctx
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const push = useCallback((t: Omit<Toast, 'id'>) => {
    const id = Date.now() + Math.random()
    setToasts((prev) => [...prev, { ...t, id }])
    if (t.duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((x) => x.id !== id))
      }, t.duration)
    }
  }, [])

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((x) => x.id !== id))
  }, [])

  const api: ToastAPI = {
    ok: (title, message) => push({ kind: 'ok', title, message, duration: 3500 }),
    error: (title, message) => push({ kind: 'error', title, message, duration: 6000 }),
    info: (title, message) => push({ kind: 'info', title, message, duration: 3500 }),
    warn: (title, message) => push({ kind: 'warn', title, message, duration: 4500 }),
  }

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((t) => (
            <ToastCard key={t.id} toast={t} onDismiss={() => remove(t.id)} />
          ))}
        </AnimatePresence>
      </div>
    </Ctx.Provider>
  )
}

function ToastCard({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  // kind → icon + border color. Keeping this as inline maps rather than a
  // separate lookup so the tailwind JIT sees the full class strings.
  const styles = {
    ok:    { icon: CheckCircle2,   border: 'border-tron-cyan/60',    accent: 'text-tron-cyan'     },
    error: { icon: XCircle,        border: 'border-status-offline',  accent: 'text-status-offline'},
    info:  { icon: Info,           border: 'border-tron-border',     accent: 'text-slate-300'     },
    warn:  { icon: AlertTriangle,  border: 'border-amber-500/60',    accent: 'text-amber-400'     },
  }[toast.kind]
  const Icon = styles.icon

  // Wake the element briefly via a scale pulse when it lands — Tron-adjacent
  // without being gaudy. Mobile-friendly: fully tappable X for manual dismiss.
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 40, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 40, scale: 0.95 }}
      transition={{ duration: 0.2 }}
      className={`pointer-events-auto min-w-[260px] max-w-sm bg-tron-panel/95 backdrop-blur border ${styles.border} rounded shadow-[0_0_24px_rgba(0,229,255,0.08)] px-3 py-2.5 flex items-start gap-2`}
    >
      <Icon size={14} className={`${styles.accent} flex-none mt-0.5`} />
      <div className="flex-1 min-w-0">
        <p className={`text-xs font-mono font-bold uppercase tracking-wider ${styles.accent}`}>
          {toast.title}
        </p>
        {toast.message && (
          <p className="text-[11px] font-mono text-slate-400 leading-snug mt-0.5 break-words">
            {toast.message}
          </p>
        )}
      </div>
      <button
        onClick={onDismiss}
        className="text-slate-500 hover:text-slate-300 transition-colors flex-none"
        aria-label="Dismiss"
      >
        <X size={12} />
      </button>
    </motion.div>
  )
}


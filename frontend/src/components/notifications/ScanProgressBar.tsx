import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useSocket } from '../../hooks/useSocket'

interface ScanProgress {
  job_id: string
  percent: number
  scan_type: string
}

interface ScanComplete {
  job_id: string
  scan_type: string
  device_count: number
}

export function ScanProgressBar() {
  const { on } = useSocket()
  const [active, setActive] = useState<ScanProgress | null>(null)
  const [flash, setFlash] = useState<string | null>(null)

  useEffect(() => {
    const offProgress = on<ScanProgress>('scan:progress', (data) => {
      setActive(data)
    })
    const offComplete = on<ScanComplete>('scan:complete', (data) => {
      setActive(null)
      setFlash(`${data.scan_type.toUpperCase()} complete — ${data.device_count} devices`)
      setTimeout(() => setFlash(null), 4000)
    })
    return () => { offProgress(); offComplete() }
  }, [on])

  return (
    <AnimatePresence>
      {active && (
        <motion.div
          key="scan-progress"
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          className="absolute top-12 left-1/2 -translate-x-1/2 z-20 bg-tron-panel border border-tron-border rounded px-4 py-2 flex items-center gap-3 shadow-tron-sm"
          style={{ minWidth: 260 }}
        >
          <span className="text-xs font-mono text-tron-cyan uppercase">{active.scan_type}</span>
          <div className="flex-1 h-1.5 bg-tron-border rounded-full overflow-hidden">
            <motion.div
              className="h-full rounded-full bg-tron-cyan"
              style={{ boxShadow: '0 0 6px rgba(0,229,255,0.8)' }}
              animate={{ width: `${active.percent}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>
          <span className="text-xs font-mono text-slate-400">{active.percent}%</span>
        </motion.div>
      )}
      {flash && !active && (
        <motion.div
          key="scan-flash"
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          className="absolute top-12 left-1/2 -translate-x-1/2 z-20 bg-tron-panel border border-status-online/40 rounded px-4 py-2 text-xs font-mono text-status-online shadow-status-online"
        >
          ✓ {flash}
        </motion.div>
      )}
    </AnimatePresence>
  )
}

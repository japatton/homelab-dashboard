import { useState, useEffect, useRef } from 'react'
import { AnimatePresence } from 'framer-motion'
import { useSocket } from '../../hooks/useSocket'
import { ClaudeIntegrationCard } from './ClaudeIntegrationCard'
import type { StagedChange } from '../../api/claudeIntegration'

export function NotificationOverlay() {
  const { on } = useSocket()
  const [stagedChanges, setStagedChanges] = useState<StagedChange[]>([])
  // Track IDs dismissed this session so socket reconnects don't re-show them
  const dismissed = useRef<Set<string>>(new Set())

  useEffect(() => {
    const off = on<StagedChange>('claude:staged', (change) => {
      if (dismissed.current.has(change.id)) return
      setStagedChanges((prev) => {
        if (prev.find((c) => c.id === change.id)) return prev
        return [...prev, change]
      })
    })
    return off
  }, [on])

  const dismiss = (id: string) => {
    dismissed.current.add(id)
    setStagedChanges((prev) => prev.filter((c) => c.id !== id))
  }

  return (
    <div className="fixed top-4 right-4 z-20 flex flex-col gap-3 pointer-events-none max-w-xs">
      <AnimatePresence>
        {stagedChanges.map((change) => (
          <div key={change.id} className="pointer-events-auto">
            <ClaudeIntegrationCard change={change} onDismiss={() => dismiss(change.id)} />
          </div>
        ))}
      </AnimatePresence>
    </div>
  )
}

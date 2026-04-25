import { useState } from 'react'
import { motion } from 'framer-motion'
import { Sparkles, ChevronDown, ChevronUp, Check, X } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { approveChange, rejectChange, type StagedChange } from '../../api/claudeIntegration'
import { GlowButton } from '../shared/GlowButton'

interface ClaudeIntegrationCardProps {
  change: StagedChange
  onDismiss: () => void
}

export function ClaudeIntegrationCard({ change, onDismiss }: ClaudeIntegrationCardProps) {
  const [expanded, setExpanded] = useState(false)
  const queryClient = useQueryClient()

  const approveMutation = useMutation({
    mutationFn: () => approveChange(change.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['staged-changes'] })
      onDismiss()
    },
  })

  const rejectMutation = useMutation({
    mutationFn: () => rejectChange(change.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['staged-changes'] })
      onDismiss()
    },
  })

  return (
    <motion.div
      initial={{ x: 400, opacity: 0, scale: 0.9 }}
      animate={{ x: 0, opacity: 1, scale: 1 }}
      exit={{ x: 400, opacity: 0, scale: 0.9 }}
      transition={{ type: 'spring', stiffness: 260, damping: 22 }}
      className="w-80 bg-tron-panel border border-tron-purple/50 rounded-lg overflow-hidden"
      style={{ boxShadow: '0 0 24px rgba(124,58,237,0.3)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-tron-purple/10 border-b border-tron-purple/30">
        <motion.div
          animate={{ rotate: [0, 15, -15, 0] }}
          transition={{ repeat: Infinity, duration: 3 }}
        >
          <Sparkles size={14} className="text-tron-purple" />
        </motion.div>
        <span className="text-xs font-mono text-tron-purple font-medium flex-1">Claude Integration Ready</span>
        <button onClick={onDismiss} className="text-slate-500 hover:text-tron-purple transition-colors">
          <X size={12} />
        </button>
      </div>

      <div className="p-3 space-y-2">
        <p className="text-xs text-slate-300 leading-relaxed">{change.reason}</p>

        <div className="text-xs text-slate-500 font-mono">
          Device: <span className="text-tron-cyan">{change.device_context?.ip as string ?? change.device_id}</span>
        </div>

        {/* Diff toggle */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 text-xs text-slate-500 hover:text-tron-cyan transition-colors font-mono"
        >
          {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {expanded ? 'Hide' : 'Show'} diff ({change.generated_files.length} file{change.generated_files.length !== 1 ? 's' : ''})
        </button>

        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            className="overflow-hidden"
          >
            <pre className="text-xs font-mono bg-tron-dark border border-tron-border rounded p-2 overflow-x-auto max-h-48 overflow-y-auto leading-relaxed">
              <code style={{ color: '#e2e8f0' }}>
                {change.diff_preview.split('\n').map((line, i) => {
                  const color = line.startsWith('+') ? '#4ade80'
                    : line.startsWith('-') ? '#f87171'
                    : line.startsWith('@@') ? '#60a5fa'
                    : '#94a3b8'
                  return (
                    <span key={i} style={{ color, display: 'block' }}>{line}</span>
                  )
                })}
              </code>
            </pre>
          </motion.div>
        )}

        {/* Actions */}
        <div className="flex gap-2 pt-1">
          <GlowButton
            variant="green"
            size="sm"
            icon={<Check size={11} />}
            loading={approveMutation.isPending}
            onClick={() => approveMutation.mutate()}
            className="flex-1 justify-center"
          >
            Apply
          </GlowButton>
          <GlowButton
            variant="red"
            size="sm"
            icon={<X size={11} />}
            loading={rejectMutation.isPending}
            onClick={() => rejectMutation.mutate()}
            className="flex-1 justify-center"
          >
            Reject
          </GlowButton>
        </div>
      </div>
    </motion.div>
  )
}

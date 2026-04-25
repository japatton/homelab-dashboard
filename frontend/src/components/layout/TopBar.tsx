import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { getNetworkStatus } from '../../api/network'
import { useSocket } from '../../hooks/useSocket'
import { Zap } from 'lucide-react'

export function TopBar({ title }: { title: string }) {
  const { socket } = useSocket()
  const { data: status } = useQuery({
    queryKey: ['network-status'],
    queryFn: getNetworkStatus,
    refetchInterval: 30_000,
  })

  const connected = socket.connected

  return (
    <header className="h-12 flex items-center justify-between px-4 bg-tron-panel border-b border-tron-border flex-shrink-0">
      <div className="flex items-center gap-3">
        <h1 className="text-tron-cyan font-mono text-sm font-medium tracking-wider uppercase">
          {title}
        </h1>
      </div>

      <div className="flex items-center gap-4">
        {status && (
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-slate-500">
              <span className="text-status-online">{status.online}</span>/{status.total} online
            </span>
            {status.unknown_type > 0 && (
              <span className="text-status-scanning">{status.unknown_type} unknown</span>
            )}
          </div>
        )}

        <div className="flex items-center gap-1.5">
          <motion.div
            animate={connected ? { scale: [1, 1.3, 1] } : {}}
            transition={{ repeat: Infinity, duration: 2 }}
            className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-status-online' : 'bg-status-offline'}`}
            style={{ boxShadow: connected ? '0 0 6px rgba(0,255,136,0.8)' : undefined }}
          />
          <span className="text-xs font-mono text-slate-500">
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
          <Zap size={10} className={connected ? 'text-tron-cyan' : 'text-slate-600'} />
        </div>
      </div>
    </header>
  )
}

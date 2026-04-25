import { memo } from 'react'
import { Handle, Position } from 'reactflow'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Router, Network, Wifi, Server, Monitor, Laptop,
  Camera, Cpu, Smartphone, CircleHelp, Bell, ShieldAlert,
  type LucideIcon,
} from 'lucide-react'
import type { NodeData } from '../../types/topology'

const deviceIcons: Record<string, LucideIcon> = {
  gateway:     Router,
  switch:      Network,
  ap:          Wifi,
  server:      Server,
  workstation: Monitor,
  laptop:      Laptop,
  camera:      Camera,
  doorbell:    Bell,
  iot:         Cpu,
  phone:       Smartphone,
  unknown:     CircleHelp,
}

const statusGlow: Record<string, string> = {
  online:   '0 0 16px rgba(0,255,136,0.5)',
  offline:  '0 0 12px rgba(255,51,51,0.4)',
  scanning: '0 0 16px rgba(255,215,0,0.5)',
  unknown:  '0 0 8px rgba(107,114,128,0.3)',
}

const statusBorder: Record<string, string> = {
  online:   '#00ff88',
  offline:  '#ff3333',
  scanning: '#ffd700',
  unknown:  '#4b5563',
}

interface DeviceNodeProps {
  data: NodeData
  selected?: boolean
}

function DeviceNodeComponent({ data, selected }: DeviceNodeProps) {
  const Icon = deviceIcons[data.device_type] ?? CircleHelp
  const hasCritical = data.vuln_critical > 0
  const hasHigh = data.vuln_high > 0
  const borderColor = selected ? '#00e5ff' : (statusBorder[data.status] ?? '#4b5563')
  const glowStyle = selected
    ? '0 0 20px rgba(0,229,255,0.7), 0 0 40px rgba(0,229,255,0.3)'
    : (statusGlow[data.status] ?? '')

  return (
    <>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />

      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 300, damping: 25 }}
        className="relative flex flex-col items-center gap-1.5 px-3 py-2.5 rounded-lg bg-tron-panel cursor-pointer select-none"
        style={{
          border: `1px solid ${borderColor}`,
          boxShadow: glowStyle,
          minWidth: 120,
          maxWidth: 160,
          transition: 'box-shadow 0.3s ease, border-color 0.3s ease',
        }}
      >
        {/* Vuln badge */}
        {(hasCritical || hasHigh) && (
          <div className="absolute -top-2 -right-2 z-10">
            <motion.div
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ repeat: Infinity, duration: 2 }}
              className={`flex items-center justify-center w-5 h-5 rounded-full text-xs font-mono ${
                hasCritical ? 'bg-red-600 text-white shadow-vuln-critical' : 'bg-orange-500 text-white'
              }`}
            >
              <ShieldAlert size={11} />
            </motion.div>
          </div>
        )}

        {/* Claude AI badge */}
        <AnimatePresence>
          {data.has_staged_integration && (
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              className="absolute -top-2 -left-2 z-10 bg-tron-purple rounded-full px-1.5 py-0.5 text-white font-mono"
              style={{ fontSize: 9, boxShadow: '0 0 8px rgba(124,58,237,0.7)' }}
            >
              AI
            </motion.div>
          )}
        </AnimatePresence>

        {/* Pulse ring for staged integration */}
        <AnimatePresence>
          {data.has_staged_integration && (
            <motion.div
              initial={{ opacity: 0.6, scale: 1 }}
              animate={{ opacity: 0, scale: 1.5 }}
              transition={{ repeat: Infinity, duration: 1.5, ease: 'easeOut' }}
              className="absolute inset-0 rounded-lg border border-tron-purple pointer-events-none"
            />
          )}
        </AnimatePresence>

        {/* Icon */}
        <div className="flex items-center justify-center w-8 h-8 rounded-md bg-tron-border/60">
          <Icon
            size={18}
            style={{ color: data.status === 'online' ? '#00e5ff' : '#6b7280' }}
          />
        </div>

        {/* Label */}
        <div className="text-center w-full">
          <div
            className="text-xs font-mono truncate leading-tight"
            style={{ color: selected ? '#00e5ff' : '#e2e8f0', maxWidth: 140 }}
          >
            {data.label}
          </div>
          {data.ip && (
            <div className="text-xs font-mono text-slate-500 truncate" style={{ fontSize: 10 }}>
              {data.ip}
            </div>
          )}
        </div>

        {/* Status dot */}
        <div className="absolute bottom-1.5 right-2">
          <span
            className="inline-block w-1.5 h-1.5 rounded-full"
            style={{
              backgroundColor: statusBorder[data.status] ?? '#4b5563',
              boxShadow: data.status === 'online' ? '0 0 4px rgba(0,255,136,0.8)' : undefined,
            }}
          />
        </div>
      </motion.div>

      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </>
  )
}

export const DeviceNode = memo(DeviceNodeComponent)

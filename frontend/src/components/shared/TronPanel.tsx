import React from 'react'
import { motion } from 'framer-motion'

interface TronPanelProps {
  children: React.ReactNode
  className?: string
  glow?: boolean
  animate?: boolean
}

export function TronPanel({ children, className = '', glow = false, animate = false }: TronPanelProps) {
  const base = `bg-tron-panel border border-tron-border rounded-lg ${glow ? 'shadow-tron-md' : ''} ${className}`

  if (animate) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ duration: 0.2 }}
        className={base}
      >
        {children}
      </motion.div>
    )
  }

  return <div className={base}>{children}</div>
}

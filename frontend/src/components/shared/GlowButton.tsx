import React from 'react'
import { motion } from 'framer-motion'

type Variant = 'cyan' | 'green' | 'red' | 'purple' | 'ghost'

interface GlowButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: 'sm' | 'md' | 'lg'
  loading?: boolean
  icon?: React.ReactNode
}

const variantStyles: Record<Variant, string> = {
  cyan:   'border-tron-cyan text-tron-cyan hover:bg-tron-cyan/10 hover:shadow-tron-sm',
  green:  'border-status-online text-status-online hover:bg-status-online/10 hover:shadow-status-online',
  red:    'border-status-offline text-status-offline hover:bg-status-offline/10 hover:shadow-status-offline',
  purple: 'border-tron-purple text-tron-purple hover:bg-tron-purple/10',
  ghost:  'border-tron-border text-slate-400 hover:border-tron-cyan/50 hover:text-tron-cyan',
}

const sizeStyles = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-2.5 text-base',
}

export function GlowButton({
  children,
  variant = 'cyan',
  size = 'md',
  loading = false,
  icon,
  className = '',
  disabled,
  ...props
}: GlowButtonProps) {
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      className={`
        inline-flex items-center gap-2 font-mono border rounded
        transition-all duration-200 cursor-pointer select-none
        disabled:opacity-40 disabled:cursor-not-allowed
        ${variantStyles[variant]} ${sizeStyles[size]} ${className}
      `}
      disabled={disabled || loading}
      {...(props as any)}
    >
      {loading ? (
        <span className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
      ) : icon}
      {children}
    </motion.button>
  )
}

import { useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { Network, Monitor, Shield, ScrollText, Settings, Activity, Brain, Bell } from 'lucide-react'
import { motion } from 'framer-motion'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import client from '../../api/client'
import { useSocket } from '../../hooks/useSocket'

interface NavItem { to: string; icon: any; label: string; badge?: number }

const baseNavItems: NavItem[] = [
  { to: '/network', icon: Network,    label: 'Network Map' },
  { to: '/devices', icon: Monitor,    label: 'Devices' },
  { to: '/vulns',   icon: Shield,     label: 'Vulnerabilities' },
  { to: '/audit',   icon: ScrollText, label: 'Audit Log' },
]

const settingsNav: NavItem = { to: '/settings', icon: Settings, label: 'Settings' }
const analysisNav: NavItem = { to: '/analysis', icon: Brain,    label: 'AI Analysis' }

export function Sidebar() {
  const qc = useQueryClient()
  const { on } = useSocket()

  // Settings fetch — used to decide whether to show the Analysis link.
  // Cheap — it's cached by tanstack-query, same query key SettingsPage uses.
  const { data: settings } = useQuery({
    queryKey: ['settings'],
    queryFn: async () => (await client.get('/settings')).data,
    staleTime: 30_000,
  })

  // Alarm summary drives the Security nav item badge. 60s polling is
  // the background safety net; the socket push below is the fast path
  // so a freshly-fired alarm ticks the badge in real time.
  const { data: alarmSummary } = useQuery<{ unacknowledged: number }>({
    queryKey: ['alarm-summary'],
    queryFn: async () => (await client.get('/alarms/summary')).data,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })

  useEffect(() => {
    const offNew = on('alarm:new', () => {
      qc.invalidateQueries({ queryKey: ['alarm-summary'] })
    })
    const offSummary = on('alarm:summary', (payload: any) => {
      // The summary payload arrives inline; write it directly so the
      // badge ticks without a round-trip. Fall back to invalidation if
      // the shape ever changes.
      if (payload?.summary?.unacknowledged != null) {
        qc.setQueryData(['alarm-summary'], payload.summary)
      } else {
        qc.invalidateQueries({ queryKey: ['alarm-summary'] })
      }
    })
    return () => { offNew(); offSummary() }
  }, [on, qc])

  const ollamaReady = !!(settings?.ollama?.enabled && settings?.ollama?.host)
  const unackCount = alarmSummary?.unacknowledged ?? 0
  // Security nav is always visible — alarms are a core product surface,
  // and hiding it when no gateway is configured would make the
  // "no alarms yet" empty state undiscoverable. We show a dot-only
  // indicator when unread > 0, with the count on hover tooltip.
  const securityNav: NavItem = {
    to: '/security',
    icon: Bell,
    label: unackCount > 0 ? `Security (${unackCount} new)` : 'Security',
    badge: unackCount,
  }

  const navItems: NavItem[] = [
    ...baseNavItems,
    securityNav,
    ...(ollamaReady ? [analysisNav] : []),
    settingsNav,
  ]

  return (
    <motion.aside
      initial={{ x: -60, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="w-14 flex flex-col items-center py-4 gap-1 bg-tron-panel border-r border-tron-border"
    >
      {/* Logo */}
      <div className="mb-4 flex items-center justify-center w-9 h-9 rounded-lg bg-tron-border/60">
        <Activity size={18} className="text-tron-cyan" style={{ filter: 'drop-shadow(0 0 6px #00e5ff)' }} />
      </div>

      {navItems.map(({ to, icon: Icon, label, badge }) => (
        <NavLink
          key={to}
          to={to}
          title={label}
          className={({ isActive }) =>
            `flex items-center justify-center w-10 h-10 rounded-lg transition-all duration-200 group relative ${
              isActive
                ? 'bg-tron-cyan/10 text-tron-cyan shadow-tron-sm'
                : 'text-slate-500 hover:text-tron-cyan hover:bg-tron-cyan/5'
            }`
          }
        >
          {({ isActive }) => (
            <>
              {isActive && (
                <motion.div
                  layoutId="sidebar-indicator"
                  className="absolute left-0 w-0.5 h-6 rounded-r bg-tron-cyan"
                  style={{ boxShadow: '0 0 8px #00e5ff' }}
                />
              )}
              <Icon size={18} />
              {/* Count-badge: only rendered when we have unacknowledged
                  items. Two-digit cap ("99+") keeps the chip compact
                  even when an alert storm is in progress. */}
              {badge != null && badge > 0 && (
                <span
                  className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-status-offline text-white text-[9px] font-mono font-bold flex items-center justify-center"
                  style={{ boxShadow: '0 0 6px rgba(239,68,68,0.6)' }}
                  role="status"
                  aria-label={`${badge} unacknowledged ${badge === 1 ? 'alarm' : 'alarms'}`}
                >
                  {badge > 99 ? '99+' : badge}
                </span>
              )}
              {/* Tooltip */}
              <span className="absolute left-14 bg-tron-panel border border-tron-border text-tron-cyan text-xs font-mono px-2 py-1 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                {label}
              </span>
            </>
          )}
        </NavLink>
      ))}
    </motion.aside>
  )
}

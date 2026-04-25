import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { NotificationOverlay } from '../notifications/NotificationOverlay'

const routeTitles: Record<string, string> = {
  '/network':  'Network Map',
  '/devices':  'Devices',
  '/vulns':    'Vulnerabilities',
  '/audit':    'Audit Log',
  '/settings': 'Settings',
}

export function AppShell() {
  const location = useLocation()
  const title = routeTitles[location.pathname] ?? 'Homelab'

  return (
    <div className="flex h-screen overflow-hidden bg-tron-dark tron-grid-bg scanline-overlay">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <TopBar title={title} />
        <main className="flex-1 relative overflow-hidden z-30">
          <Outlet />
        </main>
      </div>
      <NotificationOverlay />
    </div>
  )
}

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AppShell } from './components/layout/AppShell'
import { NetworkMapPage } from './pages/NetworkMapPage'
import { DevicesPage } from './pages/DevicesPage'
import { VulnsPage } from './pages/VulnsPage'
import { SecurityPage } from './pages/SecurityPage'
import { AuditLogPage } from './pages/AuditLogPage'
import { SettingsPage } from './pages/SettingsPage'
import { SetupPage } from './pages/SetupPage'
import { AnalysisPage } from './pages/AnalysisPage'
import { ToastProvider } from './components/shared/Toast'
import client from './api/client'

function SetupGuard({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useQuery({
    queryKey: ['setup-status'],
    queryFn: async () => (await client.get('/setup/status')).data,
    staleTime: 30_000,
  })

  if (isLoading) return null
  if (!data?.setup_complete) return <Navigate to="/setup" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      {/* ToastProvider wraps everything so any route (plus the setup
          wizard) can fire toasts. Kept inside BrowserRouter since toast
          actions occasionally want router context, though the current
          api doesn't. */}
      <ToastProvider>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route element={
            <SetupGuard>
              <AppShell />
            </SetupGuard>
          }>
            <Route index element={<Navigate to="/network" replace />} />
            <Route path="/network"  element={<NetworkMapPage />} />
            <Route path="/devices"  element={<DevicesPage />} />
            <Route path="/vulns"    element={<VulnsPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/audit"    element={<AuditLogPage />} />
            <Route path="/analysis" element={<AnalysisPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </ToastProvider>
    </BrowserRouter>
  )
}

export type ScanType = 'nmap' | 'openvas' | 'unifi'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'
export type ScanProfile = 'quick' | 'standard' | 'full'

export interface ScanJob {
  id: string
  scan_type: ScanType
  status: ScanStatus
  profile: ScanProfile
  targets?: string[]
  started_at?: string
  completed_at?: string
  progress: number
  error?: string
}

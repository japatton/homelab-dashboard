export type DeviceType =
  | 'gateway' | 'switch' | 'ap' | 'server' | 'workstation'
  | 'laptop' | 'camera' | 'doorbell' | 'iot' | 'phone' | 'unknown'

export type DeviceStatus = 'online' | 'offline' | 'scanning' | 'unknown'

export interface DeviceService {
  port: number
  protocol: string
  name: string
  version: string
  launch_url?: string
}

export interface VulnSummary {
  critical: number
  high: number
  medium: number
  low: number
}

export interface Device {
  id: string
  mac?: string
  ip?: string
  hostname?: string
  label?: string
  device_type: DeviceType
  status: DeviceStatus
  confidence: number
  services: DeviceService[]
  vuln_summary: VulnSummary
  metadata: Record<string, unknown>
  first_seen?: string
  last_seen?: string
  is_online: boolean
}

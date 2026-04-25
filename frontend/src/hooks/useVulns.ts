import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSocket } from './useSocket'
import client from '../api/client'
import type { VulnResult } from '../types/vulnerability'

interface VulnFilters {
  severity?: string
  device_id?: string
  limit?: number
  offset?: number
}

interface VulnStats {
  total: number
  devices_affected: number
  critical: number
  high: number
  medium: number
  low: number
}

interface VulnUpdatedEvent {
  device_id: string
  count: number
}

export function useVulns(filters: VulnFilters = {}) {
  const qc = useQueryClient()
  const { on } = useSocket()

  const query = useQuery<VulnResult[]>({
    queryKey: ['vulns', filters],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (filters.severity) params.set('severity', filters.severity)
      if (filters.device_id) params.set('device_id', filters.device_id)
      if (filters.limit)  params.set('limit', String(filters.limit))
      if (filters.offset) params.set('offset', String(filters.offset))
      return (await client.get(`/vulns?${params}`)).data
    },
    staleTime: 60_000,
  })

  useEffect(() => {
    return on<VulnUpdatedEvent>('vuln:updated', () => {
      qc.invalidateQueries({ queryKey: ['vulns'] })
      qc.invalidateQueries({ queryKey: ['vuln-stats'] })
    })
  }, [on, qc])

  return query
}

export function useVulnStats() {
  const qc = useQueryClient()
  const { on } = useSocket()

  const query = useQuery<VulnStats>({
    queryKey: ['vuln-stats'],
    queryFn: async () => (await client.get('/vulns/stats')).data,
    staleTime: 60_000,
  })

  useEffect(() => {
    return on<VulnUpdatedEvent>('vuln:updated', () => {
      qc.invalidateQueries({ queryKey: ['vuln-stats'] })
    })
  }, [on, qc])

  return query
}

export function useDeviceVulns(deviceId: string | null) {
  return useQuery<VulnResult[]>({
    queryKey: ['device-vulns', deviceId],
    queryFn: async () => (await client.get(`/vulns/device/${deviceId}`)).data,
    enabled: !!deviceId,
    staleTime: 30_000,
  })
}

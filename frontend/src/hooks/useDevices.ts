import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getDevices, getDevice } from '../api/devices'
import { useSocket } from './useSocket'
import type { Device } from '../types/device'

export function useDevices(filters?: { search?: string; device_type?: string }) {
  const queryClient = useQueryClient()
  const { on } = useSocket()

  const { data, isLoading, error } = useQuery<Device[]>({
    queryKey: ['devices', filters],
    queryFn: () => getDevices({ ...filters, limit: 500 }),
    refetchInterval: 30_000,
  })

  useEffect(() => {
    const off = on<Device>('device:updated', (device) => {
      queryClient.setQueryData<Device[]>(['devices', filters], (prev) => {
        if (!prev) return [device]
        const idx = prev.findIndex((d) => d.id === device.id)
        if (idx >= 0) {
          const next = [...prev]
          next[idx] = device
          return next
        }
        return [...prev, device]
      })
    })
    return off
  }, [on, queryClient, filters])

  return { devices: data ?? [], isLoading, error }
}

export function useDevice(id: string | null) {
  return useQuery<Device>({
    queryKey: ['device', id],
    queryFn: () => getDevice(id!),
    enabled: !!id,
    staleTime: 10_000,
  })
}

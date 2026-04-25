import client from './client'
import type { Device } from '../types/device'

export const getDevices = async (params?: {
  search?: string
  device_type?: string
  status?: string
  page?: number
  limit?: number
}): Promise<Device[]> => {
  const res = await client.get<Device[]>('/devices', { params })
  return res.data
}

export const getDevice = async (id: string): Promise<Device> => {
  const res = await client.get<Device>(`/devices/${id}`)
  return res.data
}

export const updateDeviceLabel = async (id: string, label: string) => {
  const res = await client.put(`/devices/${id}/label`, { label })
  return res.data
}

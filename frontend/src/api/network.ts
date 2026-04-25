import client from './client'
import type { TopologyGraph } from '../types/topology'

export const getTopology = async (): Promise<TopologyGraph> => {
  const res = await client.get<TopologyGraph>('/network/topology')
  return res.data
}

export const savePositions = async (positions: Record<string, { x: number; y: number }>) => {
  await client.put('/network/topology/positions', positions)
}

export const getNetworkStatus = async () => {
  const res = await client.get('/network/status')
  return res.data
}

export interface LatencySample {
  ts: string
  latency_ms: number | null
}

export interface LatencyResponse {
  device_id: string | null
  device_label: string | null
  samples: LatencySample[]
}

export const getLatency = async (
  opts: { device_id?: string; window_minutes?: number } = {},
): Promise<LatencyResponse> => {
  const res = await client.get<LatencyResponse>('/network/latency', { params: opts })
  return res.data
}

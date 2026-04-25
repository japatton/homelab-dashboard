import { useEffect, useCallback, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getTopology, savePositions } from '../api/network'
import { useSocket } from './useSocket'
import type { TopologyGraph, NetworkNode } from '../types/topology'

const DEBOUNCE_MS = 1000

export function useTopology() {
  const queryClient = useQueryClient()
  const { on } = useSocket()
  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const { data, isLoading, error } = useQuery<TopologyGraph>({
    queryKey: ['topology'],
    queryFn: getTopology,
    refetchInterval: 60_000,
  })

  // Merge live topology updates from Socket.io
  useEffect(() => {
    const off = on<TopologyGraph>('topology:updated', (graph) => {
      queryClient.setQueryData<TopologyGraph>(['topology'], graph)
    })
    return off
  }, [on, queryClient])

  const handlePositionChange = useCallback((nodes: NetworkNode[]) => {
    clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      const positions: Record<string, { x: number; y: number }> = {}
      nodes.forEach((n) => {
        positions[n.id] = n.position
      })
      savePositions(positions).catch(() => {/* ignore save errors */})
    }, DEBOUNCE_MS)
  }, [])

  return {
    nodes: data?.nodes ?? [],
    edges: data?.edges ?? [],
    lastUpdated: data?.last_updated,
    isLoading,
    error,
    onNodesChange: handlePositionChange,
  }
}

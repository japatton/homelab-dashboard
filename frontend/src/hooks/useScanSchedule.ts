import { useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSocket } from './useSocket'
import client from '../api/client'

interface JobInfo {
  id: string
  next_run: string | null
  paused?: boolean
}

interface SchedulerStatus {
  running: boolean
  mock: boolean
  jobs: JobInfo[]
}

interface SchedulerTick {
  job_id: string
  next_run: string
}

export function useScanSchedule() {
  const { on } = useSocket()
  const qc = useQueryClient()

  const { data: status, refetch } = useQuery<SchedulerStatus>({
    queryKey: ['scheduler-status'],
    queryFn: async () => (await client.get('/scheduler/status')).data,
    refetchInterval: 30_000,
  })

  // Live scheduler tick events
  useEffect(() => {
    return on<SchedulerTick>('scheduler:tick', () => {
      qc.invalidateQueries({ queryKey: ['scheduler-status'] })
    })
  }, [on, qc])

  const triggerJob = useMutation({
    mutationFn: (jobId: string) => client.post(`/scheduler/trigger/${jobId}`),
    onSuccess: () => refetch(),
  })

  const updateIntervals = useMutation({
    mutationFn: (vals: { nmap_minutes?: number; unifi_seconds?: number }) =>
      client.put('/scheduler/intervals', vals),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings'] })
      refetch()
    },
  })

  const jobMap = Object.fromEntries((status?.jobs ?? []).map((j) => [j.id, j]))

  return {
    status,
    jobMap,
    triggerJob: triggerJob.mutate,
    updateIntervals: updateIntervals.mutate,
    isTriggering: triggerJob.isPending,
  }
}

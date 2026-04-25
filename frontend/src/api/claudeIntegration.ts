import client from './client'

export interface StagedChange {
  id: string
  triggered_at: string
  device_id: string
  device_context: Record<string, unknown>
  reason: string
  diff_preview: string
  generated_files: string[]
  status: 'pending' | 'approved' | 'rejected' | 'applied'
  reviewed_at?: string
}

export const getStagedChanges = async (): Promise<StagedChange[]> => {
  const res = await client.get<StagedChange[]>('/claude/staged')
  return res.data
}

export const approveChange = async (changeId: string) => {
  const res = await client.post(`/claude/approve/${changeId}`)
  return res.data
}

export const rejectChange = async (changeId: string) => {
  const res = await client.post(`/claude/reject/${changeId}`)
  return res.data
}

export const getAuditLog = async () => {
  const res = await client.get('/claude/audit')
  return res.data
}

export const getChangeHistory = async (): Promise<StagedChange[]> => {
  const res = await client.get<StagedChange[]>('/claude/history')
  return res.data
}

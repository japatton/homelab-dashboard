export interface NodePosition {
  x: number
  y: number
}

export interface NodeData {
  device_id: string
  label: string
  device_type: string
  status: string
  ip?: string
  mac?: string
  services_count: number
  vuln_critical: number
  vuln_high: number
  has_staged_integration: boolean
  metadata: Record<string, unknown>
}

export interface NetworkNode {
  id: string
  type: string
  position: NodePosition
  data: NodeData
  draggable: boolean
}

export type ConnectionType = 'wired' | 'wireless'

export interface EdgeData {
  connection_type: ConnectionType
  bandwidth_mbps?: number
  signal_strength?: number
  port_number?: number
  is_active: boolean
}

export interface NetworkEdge {
  id: string
  source: string
  target: string
  type: string
  animated: boolean
  data: EdgeData
}

export interface TopologyGraph {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
  last_updated?: string
}

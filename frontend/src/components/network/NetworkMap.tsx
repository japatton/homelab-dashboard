import { useState, useCallback, useEffect, useMemo } from 'react'
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type NodeChange,
  type Node,
  type Edge,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { useTopology } from '../../hooks/useTopology'
import { DeviceNode } from './DeviceNode'
import { ConnectionEdge } from './ConnectionEdge'
import { DeviceDetailPanel } from './DeviceDetailPanel'
import { LatencyChart } from './LatencyChart'
import { LoadingGrid } from '../shared/LoadingGrid'
import type { NodeData } from '../../types/topology'

// Hoisted once — React Flow warns loudly if these objects get recreated on each render.
const nodeTypes = { deviceNode: DeviceNode }
const edgeTypes = { connectionEdge: ConnectionEdge }

// Above this node count, we disable edge animations and switch to cheap
// straight lines. Empirically tolerable for 150+ device homelabs.
const ANIMATION_NODE_THRESHOLD = 60

export function NetworkMap() {
  const { nodes: topologyNodes, edges: topologyEdges, isLoading, onNodesChange: savePositions } = useTopology()
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null)

  const largeGraph = topologyNodes.length > ANIMATION_NODE_THRESHOLD

  // Build React Flow node/edge lists from topology, memoized by identity.
  // Crucially: `selectedDeviceId` is NOT in the deps — that used to rebuild
  // every node on every click, which was the main click-sluggishness source.
  const rfNodes = useMemo<Node<NodeData>[]>(
    () =>
      topologyNodes.map((n) => ({
        id: n.id,
        type: 'deviceNode',
        position: n.position,
        data: n.data,
        draggable: true,
      })),
    [topologyNodes],
  )

  const rfEdges = useMemo<Edge[]>(
    () =>
      topologyEdges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        type: 'connectionEdge',
        animated: !largeGraph && e.animated,
        data: e.data,
      })),
    [topologyEdges, largeGraph],
  )

  const [nodes, setNodes, onNodesChange] = useNodesState<NodeData>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useEffect(() => { setNodes(rfNodes) }, [rfNodes, setNodes])
  useEffect(() => { setEdges(rfEdges) }, [rfEdges, setEdges])

  const handleNodesChange = useCallback((changes: NodeChange[]) => {
    onNodesChange(changes)
    const posChanges = changes.filter((c) => c.type === 'position' && (c as any).dragging === false)
    if (posChanges.length > 0) {
      const updated: Node<NodeData>[] = []
      setNodes((prev) => { updated.push(...prev); return prev })
      savePositions(
        updated.map((n) => ({
          id: n.id,
          position: n.position,
          data: n.data,
          type: n.type ?? 'deviceNode',
          draggable: true,
        })),
      )
    }
  }, [onNodesChange, savePositions, setNodes])

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedDeviceId((prev) => prev === node.id ? null : node.id)
  }, [])

  const handlePaneClick = useCallback(() => {
    setSelectedDeviceId(null)
  }, [])

  const defaultEdgeOptions = useMemo(
    () => (largeGraph ? { type: 'straight' as const } : undefined),
    [largeGraph],
  )

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-tron-dark tron-grid-bg h-full">
        <div className="w-64">
          <LoadingGrid rows={3} />
          <p className="text-center text-tron-cyan font-mono text-xs mt-4 animate-pulse">
            Scanning network...
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={handleNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onPaneClick={handlePaneClick}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        // Only render nodes/edges currently in the viewport — major perf win at 150+ nodes.
        onlyRenderVisibleElements
        defaultEdgeOptions={defaultEdgeOptions}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.1}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={40}
          size={1}
          color="rgba(0,229,255,0.08)"
        />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => {
            const status = (n.data as NodeData)?.status
            return status === 'online' ? '#00ff88'
              : status === 'offline' ? '#ff3333'
              : '#6b7280'
          }}
          maskColor="rgba(2,12,27,0.7)"
        />
      </ReactFlow>

      <LatencyChart />

      <DeviceDetailPanel
        deviceId={selectedDeviceId}
        onClose={() => setSelectedDeviceId(null)}
      />
    </div>
  )
}

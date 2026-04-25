import { useMemo, useRef, useState, Suspense } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import {
  OrbitControls,
  Html,
  PerformanceMonitor,
  AdaptiveDpr,
} from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { useTopology } from '../../hooks/useTopology'
import { DeviceDetailPanel } from './DeviceDetailPanel'
import { LoadingGrid } from '../shared/LoadingGrid'
import type { NodeData } from '../../types/topology'

// ──────────────────────────────────────────────────────────────────────────────
// GridSphere — the "Tron Grid" 3D topology view.
//
// Devices sit on a Fibonacci-distributed sphere (even angular spacing at any
// node count). Users grab + drag to orbit; camera has damping so it spins
// freely with momentum. Device labels are rendered as DOM overlays via drei's
// <Html> so they're always horizon-aligned (DOM doesn't rotate with the 3D
// scene) and play nicely with our strict Content-Security-Policy (the older
// <Text> path fetches a default font from a CDN which gets blocked).
//
// Perf tactics in play:
// - dpr=[1, 2] cap (retina screens don't need 3× pixel budget)
// - <PerformanceMonitor> dials dpr down under sustained low FPS
// - <AdaptiveDpr> kicks in during active orbit (lower res while dragging)
// - Wireframe sphere shell = one geometry, one draw call
// - Bloom wrapped in its own <Suspense> so a shader-compile hiccup on a
//   weak GPU doesn't nuke the whole scene (we still see the sphere).
// - Equator + meridian lines are plain <torus>es sharing one material
//
// Intentionally NOT instanced: the nodes carry per-node <Html>, per-node
// click handlers, and per-node color. InstancedMesh would force us to lift
// all of that out into shaders and custom picking. The threshold where
// that pays off (~150+ nodes) is above a realistic homelab.
// ──────────────────────────────────────────────────────────────────────────────

const SPHERE_RADIUS = 5
const NODE_SIZE = 0.18
const LABEL_OFFSET_Y = 0.4

// Tron palette — keep in sync with tailwind.config.js tron.* tokens.
const COLORS = {
  cyan: '#00e5ff',
  cyanDim: '#0891b2',
  grid: '#1e3a5f',
  red: '#ef4444',
  orange: '#f97316',
  grey: '#64748b',
  green: '#22c55e',
  panel: '#020c1b',
} as const

function statusColor(status: string, critical: number, high: number): string {
  if (critical > 0) return COLORS.red
  if (high > 0) return COLORS.orange
  if (status === 'online') return COLORS.cyan
  if (status === 'offline') return COLORS.red
  return COLORS.grey
}

// Fibonacci sphere distribution. Deterministic in index order so the same
// device lands in the same spot on re-render — avoids the icons swapping
// places every refresh which would be jarring and disorienting.
function fibonacciSphere(count: number, radius: number): THREE.Vector3[] {
  const out: THREE.Vector3[] = []
  if (count <= 0) return out
  if (count === 1) return [new THREE.Vector3(0, 0, radius)]

  const phi = Math.PI * (Math.sqrt(5) - 1) // golden angle
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2 // range [1, -1]
    const r = Math.sqrt(1 - y * y)
    const theta = phi * i
    out.push(new THREE.Vector3(
      Math.cos(theta) * r * radius,
      y * radius,
      Math.sin(theta) * r * radius,
    ))
  }
  return out
}

// ──────────────────────────────────────────────────────────────────────────────
// Sphere chrome (wireframe, equator, meridians, floor grid)
// ──────────────────────────────────────────────────────────────────────────────

function SphereShell() {
  // Low-poly wireframe; the illusion of a grid-sphere comes from the
  // overlaid equator + meridians, not from geometry density.
  return (
    <mesh>
      <sphereGeometry args={[SPHERE_RADIUS, 24, 16]} />
      <meshBasicMaterial
        color={COLORS.grid}
        wireframe
        transparent
        opacity={0.25}
      />
    </mesh>
  )
}

function Ring({ rotation, color = COLORS.cyan, opacity = 0.45 }: {
  rotation?: [number, number, number]
  color?: string
  opacity?: number
}) {
  return (
    <mesh rotation={rotation}>
      <torusGeometry args={[SPHERE_RADIUS, 0.008, 8, 128]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={opacity}
        toneMapped={false}
      />
    </mesh>
  )
}

function SphereFrame() {
  // Equator + 2 meridians → minimal geometry, maximum "Tron grid" read.
  return (
    <group>
      <Ring /> {/* equator */}
      <Ring rotation={[Math.PI / 2, 0, 0]} opacity={0.3} color={COLORS.cyanDim} />
      <Ring rotation={[0, 0, Math.PI / 2]} opacity={0.3} color={COLORS.cyanDim} />
    </group>
  )
}

function FloorGrid() {
  // Sits well below the sphere to give the eye a horizon reference —
  // otherwise rotation feels weightless and nauseous.
  return (
    <gridHelper
      args={[40, 40, COLORS.cyan, COLORS.grid]}
      position={[0, -SPHERE_RADIUS - 3, 0]}
    />
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Device node (3D orb + DOM label)
// ──────────────────────────────────────────────────────────────────────────────

function DeviceOrb({
  position,
  color,
  hovered,
  selected,
}: {
  position: THREE.Vector3
  color: string
  hovered: boolean
  selected: boolean
}) {
  const meshRef = useRef<THREE.Mesh>(null)

  // Gentle pulse on selection; costs nothing (per-frame scale write).
  useFrame((state) => {
    if (!meshRef.current) return
    const t = state.clock.elapsedTime
    const pulse = selected ? 1 + Math.sin(t * 4) * 0.1 : 1
    const base = hovered ? 1.4 : 1
    meshRef.current.scale.setScalar(base * pulse)
  })

  return (
    <mesh ref={meshRef} position={position}>
      <octahedronGeometry args={[NODE_SIZE, 0]} />
      <meshStandardMaterial
        color={color}
        emissive={color}
        emissiveIntensity={hovered || selected ? 2.4 : 1.2}
        metalness={0.4}
        roughness={0.3}
        toneMapped={false}
      />
    </mesh>
  )
}

// Far-side hiding: we want labels on the hemisphere facing away from the
// camera to fade out rather than bleed through the wireframe. Cheapest way
// to do that without reading the depth buffer is a per-frame dot-product
// between the node's outward normal (its own position from origin) and the
// view vector (node - camera). Positive → facing away → hide.
function useFacingCamera(position: THREE.Vector3) {
  const hiddenRef = useRef(false)
  useFrame((state) => {
    const cam = state.camera.position
    const dot =
      position.x * (position.x - cam.x) +
      position.y * (position.y - cam.y) +
      position.z * (position.z - cam.z)
    hiddenRef.current = dot >= 0
  })
  return hiddenRef
}

function DeviceLabel({
  position,
  text,
  color,
}: {
  position: THREE.Vector3
  text: string
  color: string
}) {
  const hiddenRef = useFacingCamera(position)
  const domRef = useRef<HTMLDivElement>(null)

  // Toggle visibility on the DOM node directly per-frame to avoid a
  // re-render every time the camera moves — that'd be catastrophic with
  // 50+ nodes. `hiddenRef` is updated inside the same frame hook.
  useFrame(() => {
    if (!domRef.current) return
    domRef.current.style.opacity = hiddenRef.current ? '0' : '1'
  })

  return (
    <Html
      position={[position.x, position.y + LABEL_OFFSET_Y, position.z]}
      center
      distanceFactor={10}
      zIndexRange={[10, 0]}
      // Don't intercept clicks — the 3D orb beneath should still be pickable.
      style={{ pointerEvents: 'none' }}
    >
      <div
        ref={domRef}
        className="px-1.5 py-0.5 rounded bg-tron-panel/80 backdrop-blur-sm border text-[10px] font-mono whitespace-nowrap select-none transition-opacity duration-150"
        style={{
          color,
          borderColor: `${color}55`,
          textShadow: `0 0 4px ${color}88`,
        }}
      >
        {text}
      </div>
    </Html>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Scene — the whole orbiting rig, minus Canvas
// ──────────────────────────────────────────────────────────────────────────────

function Scene({
  positions,
  nodes,
  selectedId,
  onSelect,
}: {
  positions: THREE.Vector3[]
  nodes: { id: string; data: NodeData }[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const [hovered, setHovered] = useState<string | null>(null)

  return (
    <>
      {/* ambient keeps unlit parts from going black; rim/top fill sell form. */}
      <ambientLight intensity={0.25} />
      <directionalLight position={[10, 10, 10]} intensity={0.4} color={COLORS.cyan} />
      <pointLight position={[0, 0, 0]} intensity={0.8} color={COLORS.cyan} distance={15} />

      <SphereShell />
      <SphereFrame />
      <FloorGrid />

      {nodes.map((n, i) => {
        const pos = positions[i]
        if (!pos) return null
        const color = statusColor(n.data.status, n.data.vuln_critical, n.data.vuln_high)
        const isHovered = hovered === n.id
        const isSelected = selectedId === n.id

        return (
          <group
            key={n.id}
            onPointerOver={(e) => { e.stopPropagation(); setHovered(n.id); document.body.style.cursor = 'pointer' }}
            onPointerOut={() => { setHovered(null); document.body.style.cursor = '' }}
            onClick={(e) => { e.stopPropagation(); onSelect(n.id) }}
          >
            <DeviceOrb
              position={pos}
              color={color}
              hovered={isHovered}
              selected={isSelected}
            />
            <DeviceLabel
              position={pos}
              text={n.data.label || n.data.ip || n.id.slice(0, 8)}
              color={color}
            />
          </group>
        )
      })}
    </>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Top-level component — Canvas + overlay UI
// ──────────────────────────────────────────────────────────────────────────────

export function GridSphere() {
  const { nodes, isLoading } = useTopology()
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null)
  const [dpr, setDpr] = useState<number>(1.5)

  // Compute node positions once per node-count change. We key on count to
  // keep positions stable as data refreshes (status changes, vuln counts)
  // without teleporting nodes around the sphere.
  const positions = useMemo(
    () => fibonacciSphere(nodes.length, SPHERE_RADIUS),
    [nodes.length],
  )

  const orderedNodes = useMemo(
    () => nodes.map((n) => ({ id: n.id, data: n.data })),
    [nodes],
  )

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-tron-dark tron-grid-bg h-full">
        <div className="w-64">
          <LoadingGrid rows={3} />
          <p className="text-center text-tron-cyan font-mono text-xs mt-4 animate-pulse">
            Initializing Grid...
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full bg-tron-dark">
      <Canvas
        dpr={dpr}
        camera={{ position: [0, 2, 14], fov: 55, near: 0.1, far: 100 }}
        gl={{ antialias: true, alpha: false, powerPreference: 'high-performance' }}
        onPointerMissed={() => setSelectedDeviceId(null)}
      >
        <color attach="background" args={[COLORS.panel]} />
        <fog attach="fog" args={[COLORS.panel, 18, 45]} />

        <PerformanceMonitor
          onDecline={() => setDpr(1)}
          onIncline={() => setDpr(1.5)}
        />
        <AdaptiveDpr pixelated={false} />

        {/* Scene is synchronous — no suspending resources — so it renders
            immediately without a fallback hiding it. */}
        <Scene
          positions={positions}
          nodes={orderedNodes}
          selectedId={selectedDeviceId}
          onSelect={(id) =>
            setSelectedDeviceId((prev) => (prev === id ? null : id))
          }
        />

        {/* Bloom in its own Suspense: if the shader compile ever fails on a
            tight-CSP'd browser or underpowered GPU, we lose the glow but
            keep the sphere. Better than a blank canvas. */}
        <Suspense fallback={null}>
          <EffectComposer multisampling={0}>
            <Bloom
              mipmapBlur
              intensity={0.7}
              luminanceThreshold={0.35}
              luminanceSmoothing={0.3}
            />
          </EffectComposer>
        </Suspense>

        <OrbitControls
          enablePan={false}
          enableZoom={true}
          enableDamping
          dampingFactor={0.08}
          rotateSpeed={0.7}
          zoomSpeed={0.8}
          minDistance={7}
          maxDistance={25}
          autoRotate
          autoRotateSpeed={0.35}
        />
      </Canvas>

      {/* HUD — minimal, so it doesn't compete with the sphere. */}
      <div className="absolute top-3 left-3 pointer-events-none">
        <div className="bg-tron-panel/80 backdrop-blur border border-tron-border/50 rounded px-2 py-1 inline-block">
          <p className="text-[10px] font-mono uppercase tracking-wider text-tron-cyan/80">
            ◢ Grid Sphere
          </p>
          <p className="text-[10px] font-mono text-slate-500 mt-0.5">
            {nodes.length} node{nodes.length === 1 ? '' : 's'} · drag to rotate · scroll to zoom
          </p>
        </div>
      </div>

      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <p className="text-slate-500 font-mono text-sm">No devices on the grid yet</p>
        </div>
      )}

      <DeviceDetailPanel
        deviceId={selectedDeviceId}
        onClose={() => setSelectedDeviceId(null)}
      />
    </div>
  )
}

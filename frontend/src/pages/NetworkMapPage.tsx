import { lazy, Suspense, useState } from 'react'
import { ScanProgressBar } from '../components/notifications/ScanProgressBar'
import { LoadingGrid } from '../components/shared/LoadingGrid'
import { Globe2, Network } from 'lucide-react'

// Lazy-load BOTH views so the initial bundle only ships whichever one the
// user lands on first. Three.js + postprocessing is ~600 kB gzipped — the
// whole reason the 3D view is worth isolating. React Flow is split too for
// symmetry and because not every session ends up on the topology page.
const GridSphere = lazy(() =>
  import('../components/network/GridSphere').then((m) => ({ default: m.GridSphere })),
)
const NetworkMap = lazy(() =>
  import('../components/network/NetworkMap').then((m) => ({ default: m.NetworkMap })),
)

// Two topology views share the same data, styled very differently:
//   • Grid Sphere — the 3D Tron "landing shot" view (default; the thing
//     that sells the product at a glance).
//   • Flow       — the old 2D React Flow graph, kept as the "just get me
//     to my device" pragmatic view with drag-to-reposition and minimap.
//
// Persisted to localStorage so the user's preference survives reloads;
// some folks will always want the flow view.

type View = 'sphere' | 'flow'
const STORAGE_KEY = 'topology:view'

function loadInitial(): View {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    return v === 'flow' ? 'flow' : 'sphere'
  } catch {
    return 'sphere'
  }
}

function ViewFallback() {
  return (
    <div className="flex-1 flex items-center justify-center bg-tron-dark tron-grid-bg h-full">
      <div className="w-64">
        <LoadingGrid rows={3} />
        <p className="text-center text-tron-cyan font-mono text-xs mt-4 animate-pulse">
          Loading view...
        </p>
      </div>
    </div>
  )
}

export function NetworkMapPage() {
  const [view, setView] = useState<View>(loadInitial)

  const pick = (v: View) => {
    setView(v)
    try { localStorage.setItem(STORAGE_KEY, v) } catch { /* storage blocked — ignore */ }
  }

  return (
    <div className="relative w-full h-full">
      <ScanProgressBar />

      {/* View switcher — top-right so it doesn't fight the Grid Sphere HUD
          (top-left) or the React Flow controls (bottom-left). */}
      <div className="absolute top-3 right-3 z-10 flex gap-1 bg-tron-panel/80 backdrop-blur border border-tron-border/50 rounded p-0.5">
        <button
          onClick={() => pick('sphere')}
          className={`px-2 py-1 rounded text-[11px] font-mono inline-flex items-center gap-1.5 transition-colors ${
            view === 'sphere'
              ? 'bg-tron-cyan/15 text-tron-cyan border border-tron-cyan/40'
              : 'text-slate-400 hover:text-slate-200 border border-transparent'
          }`}
          title="3D Grid Sphere"
        >
          <Globe2 size={11} /> Sphere
        </button>
        <button
          onClick={() => pick('flow')}
          className={`px-2 py-1 rounded text-[11px] font-mono inline-flex items-center gap-1.5 transition-colors ${
            view === 'flow'
              ? 'bg-tron-cyan/15 text-tron-cyan border border-tron-cyan/40'
              : 'text-slate-400 hover:text-slate-200 border border-transparent'
          }`}
          title="2D Flow Graph"
        >
          <Network size={11} /> Flow
        </button>
      </div>

      <Suspense fallback={<ViewFallback />}>
        {view === 'sphere' ? <GridSphere /> : <NetworkMap />}
      </Suspense>
    </div>
  )
}

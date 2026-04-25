export function LoadingGrid({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3 animate-pulse">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-16 bg-tron-border/40 rounded-lg" style={{ opacity: 1 - i * 0.2 }} />
      ))}
    </div>
  )
}

export function LoadingNode() {
  return (
    <div className="w-40 h-20 rounded-lg bg-tron-panel border border-tron-border animate-pulse" />
  )
}

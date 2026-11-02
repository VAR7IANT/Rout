import { useId } from 'react'

interface Series {
  values: number[]
  className: string
  label: string
}

/** A flat line chart (no gradients). Series share one scale starting at zero. */
export function LineChart({ series, height = 64, label, max }: { series: Series[]; height?: number; label: string; max?: number }) {
  const id = useId()
  const w = 240
  const n = Math.max(0, ...series.map((s) => s.values.length))
  if (n < 2) {
    return <div className="chart chart-empty" style={{ height }} role="img" aria-label={label} />
  }
  const top = max ?? Math.max(1, ...series.flatMap((s) => s.values))
  const step = w / (n - 1)
  const y = (v: number) => height - 2 - (Math.min(v, top) / top) * (height - 4)
  return (
    <svg className="chart" viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" role="img" aria-label={label} style={{ height }}>
      <title id={id}>{label}</title>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={w} y1={height * f} y2={height * f} className="chart-grid" />
      ))}
      {series.map((s) => {
        const off = n - s.values.length
        const pts = s.values.map((v, i) => `${((i + off) * step).toFixed(1)},${y(v).toFixed(1)}`)
        return (
          <g key={s.label} className={s.className}>
            <polygon className="chart-area" points={`${(off * step).toFixed(1)},${height} ${pts.join(' ')} ${w},${height}`} />
            <polyline className="chart-line" points={pts.join(' ')} fill="none" vectorEffect="non-scaling-stroke" />
          </g>
        )
      })}
    </svg>
  )
}

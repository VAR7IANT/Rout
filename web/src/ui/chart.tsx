export interface Series {
  label: string
  values: number[]
  /** 'a' is the accent colour, 'b' the secondary one. */
  tone: 'a' | 'b'
}

const WIDTH = 240

/**
 * A stepped line chart, like a terminal plot: no smoothing, no gradients. All series share a
 * scale that starts at zero; shorter series are right-aligned so "now" is always the right edge.
 */
export function Plot({ series, label, height = 72, max }: { series: Series[]; label: string; height?: number; max?: number }) {
  const points = Math.max(0, ...series.map((s) => s.values.length))
  if (points < 2) return <div className="plot plot--empty" style={{ height }} role="img" aria-label={label} />
  const top = max ?? Math.max(1, ...series.flatMap((s) => s.values))
  const dx = WIDTH / (points - 1)
  const y = (v: number) => height - 2 - (Math.min(Math.max(v, 0), top) / top) * (height - 4)
  return (
    <svg className="plot" viewBox={`0 0 ${WIDTH} ${height}`} preserveAspectRatio="none" role="img" aria-label={label} style={{ height }}>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} className="plot__grid" x1="0" x2={WIDTH} y1={height * f} y2={height * f} />
      ))}
      {series.map((s) => {
        const skip = points - s.values.length
        // Horizontal then vertical: each sample holds its value until the next one.
        let d = ''
        s.values.forEach((v, i) => {
          const x = ((i + skip) * dx).toFixed(1)
          d += i === 0 ? `M${x} ${y(v).toFixed(1)}` : `H${x}V${y(v).toFixed(1)}`
        })
        return <path key={s.label} className={`plot__line plot__line--${s.tone}`} d={d} fill="none" vectorEffect="non-scaling-stroke" />
      })}
    </svg>
  )
}

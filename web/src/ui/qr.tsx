import { useMemo } from 'react'
import qrcode from 'qrcode-generator'

/**
 * The QR code of `text` as one SVG path: each run of dark modules in a row becomes a single
 * rectangle. Returns null when the text does not fit in a QR code.
 */
export function qrShape(text: string): { d: string; size: number } | null {
  try {
    const code = qrcode(0, 'M')
    code.addData(text)
    code.make()
    const n = code.getModuleCount()
    const parts: string[] = []
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; ) {
        if (!code.isDark(row, col)) {
          col++
          continue
        }
        let end = col
        while (end < n && code.isDark(row, end)) end++
        parts.push(`M${col} ${row}h${end - col}v1h-${end - col}z`)
        col = end
      }
    }
    return { d: parts.join(''), size: n }
  } catch {
    return null
  }
}

const QUIET = 3 // modules of white margin scanners need

/**
 * Drawn in the browser: the link or token never leaves the page. Always black on white,
 * whatever the theme, because scanners need the contrast.
 */
export function QR({ text, label, size = 208 }: { text: string; label: string; size?: number }) {
  const shape = useMemo(() => qrShape(text), [text])
  if (!shape) return null
  const box = shape.size + QUIET * 2
  return (
    <svg className="qr" width={size} height={size} viewBox={`${-QUIET} ${-QUIET} ${box} ${box}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect x={-QUIET} y={-QUIET} width={box} height={box} fill="#fff" />
      <path d={shape.d} fill="#000" />
    </svg>
  )
}

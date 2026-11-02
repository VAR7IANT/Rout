import { useMemo } from 'react'
import qrcode from 'qrcode-generator'

/** Builds the SVG path of a QR code: one square per dark module. */
export function qrPath(text: string): { d: string; size: number } | null {
  try {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    const n = qr.getModuleCount()
    let d = ''
    for (let r = 0; r < n; r++) {
      let c = 0
      while (c < n) {
        if (!qr.isDark(r, c)) {
          c++
          continue
        }
        let end = c
        while (end < n && qr.isDark(r, end)) end++
        d += `M${c} ${r}h${end - c}v1h-${end - c}z`
        c = end
      }
    }
    return { d, size: n }
  } catch {
    // Too much data for a QR code.
    return null
  }
}

/** A QR code drawn client-side: the text never leaves the browser. */
export function QRView({ text, label, size = 208 }: { text: string; label: string; size?: number }) {
  const qr = useMemo(() => qrPath(text), [text])
  if (!qr) return null
  const quiet = 3
  const box = qr.size + quiet * 2
  return (
    <svg className="qr" width={size} height={size} viewBox={`${-quiet} ${-quiet} ${box} ${box}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect x={-quiet} y={-quiet} width={box} height={box} fill="#ffffff" />
      <path d={qr.d} fill="#1c1c1b" />
    </svg>
  )
}

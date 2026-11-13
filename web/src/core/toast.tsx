import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'

// Feedback is printed like log lines in the corner: "[ok] saved", "[err] …".
export type ToastKind = 'ok' | 'error' | 'info'
interface Line {
  id: number
  kind: ToastKind
  text: string
}
interface Toasts {
  push: (kind: ToastKind, text: string) => void
}
const Ctx = createContext<Toasts | null>(null)

const tag: Record<ToastKind, string> = { ok: 'ok', error: 'err', info: 'inf' }
const KEEP = 4

export function ToastProvider({ children }: { children: ReactNode }) {
  const [lines, setLines] = useState<Line[]>([])
  const seq = useRef(0)
  const drop = useCallback((id: number) => setLines((l) => l.filter((x) => x.id !== id)), [])
  const push = useCallback(
    (kind: ToastKind, text: string) => {
      const id = ++seq.current
      setLines((l) => [...l.slice(1 - KEEP), { id, kind, text }])
      // Errors stay long enough to be read and copied.
      window.setTimeout(() => drop(id), kind === 'error' ? 8000 : 3500)
    },
    [drop],
  )
  const value = useMemo(() => ({ push }), [push])
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {lines.map((l) => (
          <button key={l.id} type="button" className={`toast toast-${l.kind}`} onClick={() => drop(l.id)}>
            <span className="toast-tag" aria-hidden="true">
              [{tag[l.kind]}]
            </span>
            <span>{l.text}</span>
          </button>
        ))}
      </div>
    </Ctx.Provider>
  )
}

export function useToast(): Toasts {
  const v = useContext(Ctx)
  if (!v) throw new Error('useToast outside ToastProvider')
  return v
}

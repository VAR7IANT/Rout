import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'

export type ToastKind = 'ok' | 'error' | 'info'
interface Toast {
  id: number
  kind: ToastKind
  text: string
}
interface Ctx {
  push: (kind: ToastKind, text: string) => void
}
const ToastContext = createContext<Ctx | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const next = useRef(1)
  const push = useCallback((kind: ToastKind, text: string) => {
    const id = next.current++
    setItems((l) => [...l.slice(-3), { id, kind, text }])
    window.setTimeout(() => setItems((l) => l.filter((x) => x.id !== id)), kind === 'error' ? 7000 : 3500)
  }, [])
  const value = useMemo(() => ({ push }), [push])
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((x) => (
          <div key={x.id} className={`toast toast-${x.kind}`}>
            {x.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): Ctx {
  const v = useContext(ToastContext)
  if (!v) throw new Error('ToastProvider is missing')
  return v
}

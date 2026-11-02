import { createContext, useCallback, useContext, useEffect, useMemo, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

// A minimal History-API router: the panel has a handful of flat pages, so a dependency is not
// worth it. The Go side serves index.html for any unknown path, so reloads keep working.

interface Ctx {
  path: string
  query: URLSearchParams
  navigate: (to: string, opts?: { replace?: boolean }) => void
}
const RouterContext = createContext<Ctx | null>(null)

export function normalizePath(p: string): string {
  const clean = p.replace(/\/+$/, '')
  return clean === '' ? '/' : clean
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [loc, setLoc] = useState(() => ({ path: normalizePath(window.location.pathname), search: window.location.search }))
  useEffect(() => {
    const onPop = () => setLoc({ path: normalizePath(window.location.pathname), search: window.location.search })
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    const u = new URL(to, window.location.origin)
    if (u.origin !== window.location.origin) return
    if (opts?.replace) window.history.replaceState(null, '', u.pathname + u.search)
    else window.history.pushState(null, '', u.pathname + u.search)
    setLoc({ path: normalizePath(u.pathname), search: u.search })
    window.scrollTo?.(0, 0)
  }, [])
  const value = useMemo(() => ({ path: loc.path, query: new URLSearchParams(loc.search), navigate }), [loc, navigate])
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

export function useRouter(): Ctx {
  const v = useContext(RouterContext)
  if (!v) throw new Error('RouterProvider is missing')
  return v
}

export function Link({ to, onClick, children, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const { navigate } = useRouter()
  const click = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    navigate(to)
  }
  return (
    <a href={to} onClick={click} {...rest}>
      {children}
    </a>
  )
}

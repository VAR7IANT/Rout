import { createContext, useCallback, useContext, useEffect, useMemo, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

// History-API routing for a handful of flat pages. The Go server answers every unknown path
// with index.html, so deep links and reloads work without hash URLs.

interface Location {
  path: string
  search: string
}
interface Router {
  path: string
  query: URLSearchParams
  go: (to: string, opts?: { replace?: boolean }) => void
}
const Ctx = createContext<Router | null>(null)

/** "/nodes/" and "/nodes" are the same page; the root stays "/". */
export function cleanPath(p: string): string {
  return p.replace(/\/+$/, '') || '/'
}

const here = (): Location => ({ path: cleanPath(window.location.pathname), search: window.location.search })

export function RouterProvider({ children }: { children: ReactNode }) {
  const [loc, setLoc] = useState<Location>(here)

  useEffect(() => {
    const sync = () => setLoc(here())
    window.addEventListener('popstate', sync)
    return () => window.removeEventListener('popstate', sync)
  }, [])

  const go = useCallback((to: string, opts?: { replace?: boolean }) => {
    const url = new URL(to, window.location.origin)
    if (url.origin !== window.location.origin) return // never leave the panel
    const target = url.pathname + url.search
    if (opts?.replace) window.history.replaceState(null, '', target)
    else window.history.pushState(null, '', target)
    setLoc({ path: cleanPath(url.pathname), search: url.search })
    window.scrollTo?.(0, 0)
  }, [])

  const value = useMemo<Router>(() => ({ path: loc.path, query: new URLSearchParams(loc.search), go }), [loc, go])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRouter(): Router {
  const v = useContext(Ctx)
  if (!v) throw new Error('useRouter outside RouterProvider')
  return v
}

/** An in-app link: a real <a href> (open in new tab still works), intercepted on a plain click. */
export function Link({ to, onClick, children, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const { go } = useRouter()
  const click = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    go(to)
  }
  return (
    <a href={to} onClick={click} {...rest}>
      {children}
    </a>
  )
}

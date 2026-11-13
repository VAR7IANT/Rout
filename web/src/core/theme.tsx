import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

// The panel is a terminal: dark is the default whatever the system prefers. "Paper" is the
// light variant for bright rooms and printing.
export type Theme = 'dark' | 'light'
const STORE = 'rout.theme'

export function readTheme(): Theme {
  try {
    // Older versions stored "system"; that now means the default.
    return localStorage.getItem(STORE) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

interface ThemeCtx {
  theme: Theme
  setTheme: (t: Theme) => void
  toggle: () => void
}
const Ctx = createContext<ThemeCtx | null>(null)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setState] = useState<Theme>(readTheme)
  const setTheme = useCallback((t: Theme) => {
    setState(t)
    try {
      localStorage.setItem(STORE, t)
    } catch {
      // Storage blocked: lasts for this page view.
    }
  }, [])
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])
  const value = useMemo<ThemeCtx>(() => ({ theme, setTheme, toggle: () => setTheme(theme === 'dark' ? 'light' : 'dark') }), [theme, setTheme])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx)
  if (!v) throw new Error('useTheme outside ThemeProvider')
  return v
}

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

export type ThemeChoice = 'system' | 'light' | 'dark'
const STORE = 'rout.theme'

function read(): ThemeChoice {
  try {
    const v = localStorage.getItem(STORE)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch {
    // ignore
  }
  return 'system'
}

interface Ctx {
  theme: ThemeChoice
  setTheme: (t: ThemeChoice) => void
}
const ThemeContext = createContext<Ctx | null>(null)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeChoice>(read)
  const setTheme = useCallback((t: ThemeChoice) => {
    setThemeState(t)
    try {
      localStorage.setItem(STORE, t)
    } catch {
      // ignore
    }
  }, [])
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'system') root.removeAttribute('data-theme')
    else root.setAttribute('data-theme', theme)
  }, [theme])
  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): Ctx {
  const v = useContext(ThemeContext)
  if (!v) throw new Error('ThemeProvider is missing')
  return v
}

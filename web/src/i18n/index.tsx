import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { setApiLang } from '../lib/api'
import { catalog, type MessageKey } from './catalog'

export type Lang = 'zh-CN' | 'zh-TW' | 'en'
export const languages: { id: Lang; label: string; html: string }[] = [
  { id: 'zh-CN', label: '简体中文', html: 'zh-Hans' },
  { id: 'zh-TW', label: '繁體中文', html: 'zh-Hant' },
  { id: 'en', label: 'English', html: 'en' },
]

const STORE = 'rout.lang'
const index: Record<Lang, number> = { 'zh-CN': 0, 'zh-TW': 1, en: 2 }

export type Vars = Record<string, string | number>
export type TFn = (key: MessageKey, vars?: Vars) => string

/** Picks the interface language from a saved choice, else from the browser's languages. */
export function detectLang(saved: string | null, browser: readonly string[]): Lang {
  if (saved === 'zh-CN' || saved === 'zh-TW' || saved === 'en') return saved
  for (const raw of browser) {
    const l = raw.toLowerCase()
    if (l.startsWith('zh-tw') || l.startsWith('zh-hk') || l.startsWith('zh-mo') || l.startsWith('zh-hant')) return 'zh-TW'
    if (l.startsWith('zh')) return 'zh-CN'
    if (l.startsWith('en')) return 'en'
  }
  return 'en'
}

export function translate(lang: Lang, key: string, vars?: Vars): string {
  const entry = (catalog as Record<string, readonly string[]>)[key]
  let s = entry ? entry[index[lang]] ?? entry[2] : key
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m))
  return s
}

/** Looks up a key that is only known at run time (a server code); returns the fallback when missing. */
export function translateOr(lang: Lang, key: string, fallback: string, vars?: Vars): string {
  return key in catalog ? translate(lang, key, vars) : fallback
}

interface Ctx {
  lang: Lang
  setLang: (l: Lang) => void
  t: TFn
  /** t for run-time keys such as `alert.cert_expired`; falls back to `fallback` (or the code). */
  tc: (key: string, fallback?: string, vars?: Vars) => string
  locale: string
}

const I18nContext = createContext<Ctx | null>(null)

function readSaved(): string | null {
  try {
    return localStorage.getItem(STORE)
  } catch {
    return null
  }
}

export function I18nProvider({ children, initial }: { children: ReactNode; initial?: Lang }) {
  const [lang, setLangState] = useState<Lang>(() => initial ?? detectLang(readSaved(), navigator.languages ?? [navigator.language]))
  setApiLang(lang)
  const setLang = useCallback((l: Lang) => {
    setLangState(l)
    try {
      localStorage.setItem(STORE, l)
    } catch {
      // Storage may be blocked; the choice then lasts for this page view only.
    }
  }, [])
  useEffect(() => {
    document.documentElement.lang = languages.find((x) => x.id === lang)?.html ?? 'en'
    document.title = 'Rout'
  }, [lang])
  const value = useMemo<Ctx>(
    () => ({
      lang,
      setLang,
      t: (key, vars) => translate(lang, key, vars),
      tc: (key, fallback, vars) => translateOr(lang, key, fallback ?? key, vars),
      locale: lang === 'en' ? 'en-US' : lang,
    }),
    [lang, setLang],
  )
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): Ctx {
  const v = useContext(I18nContext)
  if (!v) throw new Error('I18nProvider is missing')
  return v
}
export function useT(): TFn {
  return useI18n().t
}
export type { MessageKey }

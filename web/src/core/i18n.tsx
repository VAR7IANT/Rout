import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { transport } from './api'
import { catalog, type MessageKey } from '../i18n/catalog'

export type Lang = 'zh-CN' | 'zh-TW' | 'en'
export type Vars = Record<string, string | number>
export type TFn = (key: MessageKey, vars?: Vars) => string
export type { MessageKey }

/** Order matters: it is the column order of every catalog entry. */
export const languages: readonly { id: Lang; label: string; short: string; html: string }[] = [
  { id: 'zh-CN', label: '简体中文', short: '简', html: 'zh-Hans' },
  { id: 'zh-TW', label: '繁體中文', short: '繁', html: 'zh-Hant' },
  { id: 'en', label: 'English', short: 'EN', html: 'en' },
]
const column = (lang: Lang) => languages.findIndex((l) => l.id === lang)
const isLang = (v: unknown): v is Lang => languages.some((l) => l.id === v)

const STORE = 'rout.lang'

/** A saved choice wins; otherwise the first browser language the panel speaks; else English. */
export function pickLang(saved: string | null, browser: readonly string[]): Lang {
  if (isLang(saved)) return saved
  for (const tag of browser) {
    const l = tag.toLowerCase()
    if (/^zh-(tw|hk|mo|hant)/.test(l)) return 'zh-TW'
    if (l.startsWith('zh')) return 'zh-CN'
    if (l.startsWith('en')) return 'en'
  }
  return 'en'
}

const table = catalog as Record<string, readonly string[]>

export function translate(lang: Lang, key: string, vars?: Vars): string {
  const entry = table[key]
  const text = entry ? (entry[column(lang)] ?? entry[2]) : key
  return vars ? text.replace(/\{(\w+)\}/g, (hole, name: string) => (name in vars ? String(vars[name]) : hole)) : text
}

interface I18n {
  lang: Lang
  setLang: (l: Lang) => void
  t: TFn
  /** For keys built at run time from a server code (`alert.cert_expired`): falls back when unknown. */
  tc: (key: string, fallback?: string, vars?: Vars) => string
  /** BCP 47 tag for Intl formatting. */
  locale: string
}
const Ctx = createContext<I18n | null>(null)

function saved(): string | null {
  try {
    return localStorage.getItem(STORE)
  } catch {
    return null
  }
}

export function I18nProvider({ children, initial }: { children: ReactNode; initial?: Lang }) {
  const [lang, setState] = useState<Lang>(() => initial ?? pickLang(saved(), navigator.languages ?? [navigator.language]))
  // Set during render so the very first request already carries the language.
  transport.setLang(lang)

  const setLang = useCallback((l: Lang) => {
    setState(l)
    try {
      localStorage.setItem(STORE, l)
    } catch {
      // Storage blocked: the choice lasts for this page view.
    }
  }, [])

  useEffect(() => {
    document.documentElement.lang = languages[column(lang)]?.html ?? 'en'
  }, [lang])

  const value = useMemo<I18n>(
    () => ({
      lang,
      setLang,
      t: (key, vars) => translate(lang, key, vars),
      tc: (key, fallback, vars) => (key in table ? translate(lang, key, vars) : (fallback ?? key)),
      locale: lang === 'en' ? 'en-US' : lang,
    }),
    [lang, setLang],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useI18n(): I18n {
  const v = useContext(Ctx)
  if (!v) throw new Error('useI18n outside I18nProvider')
  return v
}
export const useT = (): TFn => useI18n().t

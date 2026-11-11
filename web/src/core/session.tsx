import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ApiError, api, isAborted, needsReauth, transport } from './api'
import { useT, type TFn } from './i18n'
import { useToast } from './toast'
import type { SessionState } from './types'

// ---- who is signed in ------------------------------------------------------------------

/** booting: first /api/state pending · guest: sign-in form · admin: the panel · offline: no answer. */
export type Phase = 'booting' | 'guest' | 'admin' | 'offline'

interface Session {
  phase: Phase
  /** False until `rout web passwd` has been run on the server. */
  configured: boolean
  /** The server saw this request arrive over HTTPS. */
  secure: boolean
  version: string
  sessionId: string
  refresh: () => Promise<void>
  login: (password: string) => Promise<void>
  logout: () => Promise<void>
}
const SessionCtx = createContext<Session | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>('booting')
  const [facts, setFacts] = useState({ configured: true, secure: false, version: '', sessionId: '' })

  const signedOut = useCallback(() => {
    transport.setCsrf('')
    setPhase('guest')
  }, [])

  const refresh = useCallback(async () => {
    let s: SessionState
    try {
      s = await api.get<SessionState>('/api/state')
    } catch {
      setPhase('offline')
      return
    }
    if (s.authenticated && s.csrf) {
      transport.setCsrf(s.csrf)
      setFacts({ configured: s.configured, secure: s.secure, version: s.version ?? '', sessionId: s.session_id ?? '' })
      setPhase('admin')
    } else {
      setFacts((f) => ({ ...f, configured: s.configured, secure: s.secure }))
      signedOut()
    }
  }, [signedOut])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // Any later call that the server answers with "unauthenticated" drops back to the form.
  useEffect(() => {
    transport.onExpired(signedOut)
    return () => transport.onExpired(null)
  }, [signedOut])

  const login = useCallback(
    async (password: string) => {
      const r = await api.post<{ csrf: string; session_id: string; version: string }>('/api/login', { password })
      transport.setCsrf(r.csrf)
      setFacts((f) => ({ ...f, version: r.version, sessionId: r.session_id }))
      setPhase('admin')
      void refresh() // also learns whether the connection counts as secure
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    // If the call fails the server session simply runs into its idle timeout; either way this
    // browser forgets the token and shows the form.
    await api.post('/api/logout').catch(() => undefined)
    signedOut()
  }, [signedOut])

  const value = useMemo<Session>(() => ({ phase, ...facts, refresh, login, logout }), [phase, facts, refresh, login, logout])
  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>
}

export function useSession(): Session {
  const v = useContext(SessionCtx)
  if (!v) throw new Error('useSession outside SessionProvider')
  return v
}

// ---- password re-entry for dangerous operations ----------------------------------------

/** Thrown when the administrator dismisses the password prompt. Callers just stop. */
export class Cancelled extends Error {
  constructor() {
    super('cancelled')
    this.name = 'Cancelled'
  }
}

interface Reauth {
  /** Runs `fn`; when the server answers `reauth_required`, asks for the password once and retries. */
  guard: <T>(fn: () => Promise<T>) => Promise<T>
}
const ReauthCtx = createContext<Reauth | null>(null)

/**
 * `prompt` renders the password dialog and calls `done(true)` after /api/reauth succeeded.
 * It is injected so this module stays free of UI code.
 */
export function ReauthProvider({ children, prompt }: { children: ReactNode; prompt: (done: (ok: boolean) => void) => ReactNode }) {
  const [asking, setAsking] = useState(false)
  const pending = useRef<((ok: boolean) => void) | null>(null)

  const done = useCallback((ok: boolean) => {
    setAsking(false)
    pending.current?.(ok)
    pending.current = null
  }, [])

  const ask = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        pending.current?.(false) // a second prompt supersedes the first
        pending.current = resolve
        setAsking(true)
      }),
    [],
  )

  const guard = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn()
      } catch (e) {
        if (!needsReauth(e)) throw e
        if (!(await ask())) throw new Cancelled()
        return fn()
      }
    },
    [ask],
  )

  const value = useMemo(() => ({ guard }), [guard])
  return (
    <ReauthCtx.Provider value={value}>
      {children}
      {asking ? prompt(done) : null}
    </ReauthCtx.Provider>
  )
}

export function useReauth(): Reauth {
  const v = useContext(ReauthCtx)
  if (!v) throw new Error('useReauth outside ReauthProvider')
  return v
}

// ---- turning failures into words -------------------------------------------------------

/** Server messages already arrive in the interface language (the client sends X-Rout-Lang). */
export function errorText(e: unknown, t: TFn): string {
  if (!(e instanceof ApiError)) return t('err.generic')
  if (e.code === 'network') return t('err.network')
  if (e.code === 'server') return t('err.server')
  if (e.code === 'rate_limited' && e.retryAfter) return t('err.rate', { s: e.retryAfter })
  return e.message || t('err.generic')
}

/**
 * Wraps an action: a failure becomes an error line, `ok` a success line. Returns undefined
 * only when it failed or the administrator backed out (a call with an empty answer returns
 * null), so callers test the result against `undefined`.
 */
export function useAct() {
  const t = useT()
  const toast = useToast()
  return useCallback(
    async <T,>(fn: () => Promise<T>, opts?: { ok?: string }): Promise<T | undefined> => {
      try {
        const result = await fn()
        if (opts?.ok) toast.push('ok', opts.ok)
        return result
      } catch (e) {
        if (!(e instanceof Cancelled) && !isAborted(e)) toast.push('error', errorText(e, t))
        return undefined
      }
    },
    [t, toast],
  )
}

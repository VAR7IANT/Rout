import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, api, isReauthRequired, onSessionLost, setCsrf } from './api'
import { useT, type TFn } from '../i18n'
import type { SessionState } from './types'
import { Button, Field, Input, Notice } from '../components/ui'
import { Overlay } from '../components/overlay'
import { useToast } from './toast'

export type Phase = 'loading' | 'anonymous' | 'authenticated' | 'unreachable'

interface SessionCtx {
  phase: Phase
  configured: boolean
  secure: boolean
  version: string
  sessionId: string
  refresh: () => Promise<void>
  login: (password: string) => Promise<void>
  logout: () => Promise<void>
}

const Ctx = createContext<SessionCtx | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>('loading')
  const [info, setInfo] = useState({ configured: true, secure: false, version: '', sessionId: '' })

  const apply = useCallback((s: SessionState) => {
    if (s.authenticated && s.csrf) {
      setCsrf(s.csrf)
      setInfo({ configured: s.configured, secure: s.secure, version: s.version ?? '', sessionId: s.session_id ?? '' })
      setPhase('authenticated')
    } else {
      setCsrf('')
      setInfo((i) => ({ ...i, configured: s.configured, secure: s.secure }))
      setPhase('anonymous')
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      apply(await api.get<SessionState>('/api/state'))
    } catch {
      setPhase('unreachable')
    }
  }, [apply])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    onSessionLost(() => {
      setCsrf('')
      setPhase('anonymous')
    })
    return () => onSessionLost(null)
  }, [])

  const login = useCallback(
    async (password: string) => {
      const r = await api.post<{ csrf: string; session_id: string; version: string }>('/api/login', { password })
      setCsrf(r.csrf)
      setInfo((i) => ({ ...i, version: r.version, sessionId: r.session_id }))
      setPhase('authenticated')
      // The state call also reports whether the connection is secure.
      void refresh()
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    try {
      await api.post('/api/logout')
    } finally {
      setCsrf('')
      setPhase('anonymous')
    }
  }, [])

  const value = useMemo(() => ({ phase, ...info, refresh, login, logout }), [phase, info, refresh, login, logout])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useSession(): SessionCtx {
  const v = useContext(Ctx)
  if (!v) throw new Error('SessionProvider is missing')
  return v
}

// ---- password re-entry for dangerous operations ----------------------------------------

/** Thrown when the administrator dismisses the password prompt; callers simply stop. */
export class Cancelled extends Error {
  constructor() {
    super('cancelled')
    this.name = 'Cancelled'
  }
}

interface ReauthCtx {
  /** Runs `fn`; if the server asks for the password again, prompts once and retries. */
  guard: <T>(fn: () => Promise<T>) => Promise<T>
}
const ReauthContext = createContext<ReauthCtx | null>(null)

export function ReauthProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const waiter = useRef<{ resolve: (ok: boolean) => void } | null>(null)

  const ask = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        waiter.current?.resolve(false)
        waiter.current = { resolve }
        setOpen(true)
      }),
    [],
  )
  const finish = useCallback((ok: boolean) => {
    setOpen(false)
    waiter.current?.resolve(ok)
    waiter.current = null
  }, [])

  const guard = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn()
      } catch (e) {
        if (!isReauthRequired(e)) throw e
        if (!(await ask())) throw new Cancelled()
        return await fn()
      }
    },
    [ask],
  )
  const value = useMemo(() => ({ guard }), [guard])
  return (
    <ReauthContext.Provider value={value}>
      {children}
      {open ? <ReauthDialog onDone={finish} /> : null}
    </ReauthContext.Provider>
  )
}

export function useReauth(): ReauthCtx {
  const v = useContext(ReauthContext)
  if (!v) throw new Error('ReauthProvider is missing')
  return v
}

function ReauthDialog({ onDone }: { onDone: (ok: boolean) => void }) {
  const t = useT()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/api/reauth', { password })
      onDone(true)
    } catch (err) {
      setError(errorText(err, t))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Overlay title={t('reauth.title')} description={t('reauth.desc')} onClose={() => onDone(false)} busy={busy}>
      <form onSubmit={submit} className="stack">
        <Field label={t('login.password')} error={error}>
          {(id, d) => <Input id={id} aria-describedby={d} data-autofocus type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
        </Field>
        <div className="row-end">
          <Button variant="ghost" onClick={() => onDone(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" busy={busy} disabled={password.length === 0}>
            {t('reauth.confirm')}
          </Button>
        </div>
      </form>
    </Overlay>
  )
}

// ---- error text ------------------------------------------------------------------------

/** Turns any thrown value into a message for the administrator. Server messages are already
 *  in the interface language (the client sends X-Rout-Lang). */
export function errorText(e: unknown, t: TFn): string {
  if (e instanceof ApiError) {
    if (e.code === 'network') return t('err.network')
    if (e.code === 'server') return t('err.server')
    if (e.code === 'rate_limited' && e.retryAfter) return t('err.rate', { s: e.retryAfter })
    return e.message || t('err.generic')
  }
  return t('err.generic')
}

/** Runs an action, reporting its failure as a toast. Returns undefined on failure or cancel. */
export function useRunner() {
  const t = useT()
  const toast = useToast()
  return useCallback(
    async <T,>(fn: () => Promise<T>, opts?: { ok?: string }): Promise<T | undefined> => {
      try {
        const r = await fn()
        if (opts?.ok) toast.push('ok', opts.ok)
        return r
      } catch (e) {
        if (e instanceof Cancelled || (e instanceof DOMException && e.name === 'AbortError')) return undefined
        toast.push('error', errorText(e, t))
        return undefined
      }
    },
    [t, toast],
  )
}

export { Notice }

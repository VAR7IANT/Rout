import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, api } from './api'

export interface Remote<T> {
  data: T | null
  error: ApiError | null
  /** True until the first answer (or failure) for the current path. */
  loading: boolean
  reload: () => Promise<void>
  /** Replace the cached value after a write that already returned the new state. */
  set: (v: T | null) => void
}

/**
 * Reads a GET endpoint and, with `every`, keeps it fresh. Refreshing pauses while the tab is
 * hidden and resumes at once when it comes back. Answers are numbered so a slow old response
 * can never overwrite a newer one.
 */
export function useRemote<T>(path: string | null, opts: { every?: number } = {}): Remote<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(path != null)
  const ticket = useRef(0)
  const mounted = useRef(true)

  const reload = useCallback(async () => {
    if (path == null) return
    const mine = ++ticket.current
    const current = () => mounted.current && mine === ticket.current
    try {
      const value = await api.get<T>(path)
      if (!current()) return
      setData(value)
      setError(null)
    } catch (e) {
      if (!current()) return
      setError(e instanceof ApiError ? e : new ApiError(0, 'network', 'network'))
    } finally {
      if (current()) setLoading(false)
    }
  }, [path])

  useEffect(() => {
    mounted.current = true
    setData(null)
    setError(null)
    setLoading(path != null)
    void reload()
    return () => {
      mounted.current = false
    }
  }, [reload, path])

  const every = opts.every
  useEffect(() => {
    if (!every || path == null) return
    const refresh = () => {
      if (!document.hidden) void reload()
    }
    const timer = window.setInterval(refresh, every)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [every, reload, path])

  return { data, error, loading, reload, set: setData }
}

/** The value, `ms` after it last changed (search boxes). */
export function useDebounced<T>(value: T, ms = 200): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), ms)
    return () => window.clearTimeout(timer)
  }, [value, ms])
  return settled
}

/** A busy flag wrapped around any async function. */
export function useBusy(): [boolean, <T>(fn: () => Promise<T>) => Promise<T>] {
  const [busy, setBusy] = useState(false)
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T> => {
    setBusy(true)
    try {
      return await fn()
    } finally {
      setBusy(false)
    }
  }, [])
  return [busy, run]
}

/** The current time, re-rendered every `ms` (relative timestamps, the status-bar clock). */
export function useNow(ms = 30000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), ms)
    return () => window.clearInterval(timer)
  }, [ms])
  return now
}

const typing = (el: EventTarget | null): boolean => el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))

/**
 * A global shortcut. `combo` is a key name ("/", "Escape") or "mod+k" (Ctrl on PC, Cmd on Mac).
 * Plain keys are ignored while the administrator is typing in a field.
 */
export function useHotkey(combo: string, handler: (e: KeyboardEvent) => void, enabled = true) {
  const latest = useRef(handler)
  latest.current = handler
  useEffect(() => {
    if (!enabled) return
    const mod = combo.startsWith('mod+')
    const key = (mod ? combo.slice(4) : combo).toLowerCase()
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() !== key) return
      if (mod ? !(e.metaKey || e.ctrlKey) : e.metaKey || e.ctrlKey || e.altKey || typing(e.target)) return
      latest.current(e)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [combo, enabled])
}

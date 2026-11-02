import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, api } from './api'

export interface Resource<T> {
  data: T | null
  error: ApiError | null
  loading: boolean
  reload: () => Promise<void>
  setData: (v: T | null) => void
}

/** Loads `path` and optionally keeps it fresh. Polling pauses while the tab is hidden, and a
 *  slow response never overwrites a newer one. */
export function useResource<T>(path: string | null, opts: { interval?: number } = {}): Resource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(path != null)
  const seq = useRef(0)
  const alive = useRef(true)

  const load = useCallback(async () => {
    if (path == null) return
    const mine = ++seq.current
    try {
      const r = await api.get<T>(path)
      if (!alive.current || mine !== seq.current) return
      setData(r)
      setError(null)
    } catch (e) {
      if (!alive.current || mine !== seq.current) return
      setError(e instanceof ApiError ? e : new ApiError(0, 'network', 'network'))
    } finally {
      if (alive.current && mine === seq.current) setLoading(false)
    }
  }, [path])

  useEffect(() => {
    alive.current = true
    setData(null)
    setError(null)
    setLoading(path != null)
    void load()
    return () => {
      alive.current = false
    }
  }, [load, path])

  const interval = opts.interval
  useEffect(() => {
    if (!interval || path == null) return
    const tick = () => {
      if (!document.hidden) void load()
    }
    const id = window.setInterval(tick, interval)
    const vis = () => {
      if (!document.hidden) void load()
    }
    document.addEventListener('visibilitychange', vis)
    return () => {
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', vis)
    }
  }, [interval, load, path])

  return { data, error, loading, reload: load, setData }
}

/** Debounces a fast-changing value (a search box). */
export function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = window.setTimeout(() => setV(value), ms)
    return () => window.clearTimeout(id)
  }, [value, ms])
  return v
}

/** Tracks a busy flag around an async function. */
export function useBusy(): [boolean, <T>(fn: () => Promise<T>) => Promise<T>] {
  const [busy, setBusy] = useState(false)
  const run = useCallback(async <T,>(fn: () => Promise<T>) => {
    setBusy(true)
    try {
      return await fn()
    } finally {
      setBusy(false)
    }
  }, [])
  return [busy, run]
}

export function useNow(intervalMs = 30000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

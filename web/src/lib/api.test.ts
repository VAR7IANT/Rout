import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, download, getCsrf, isReauthRequired, onSessionLost, setApiLang, setCsrf } from './api'
import { mockFetch } from '../test-utils'

afterEach(() => {
  vi.unstubAllGlobals()
  onSessionLost(null)
  setCsrf('')
  setApiLang('zh-CN')
})

describe('request headers', () => {
  beforeEach(() => {
    setCsrf('tok-123')
    setApiLang('en')
  })
  it('sends the language on every call but the CSRF token only on writes', async () => {
    const m = mockFetch({ 'GET /api/x': () => ({ body: { ok: 1 } }), 'POST /api/x': () => ({ body: null }), 'DELETE /api/x': () => ({}) })
    vi.stubGlobal('fetch', m.impl)
    await api.get('/api/x')
    await api.post('/api/x', { a: 1 })
    await api.del('/api/x')
    const [get, post, del] = m.calls
    expect(get!.headers['X-Rout-Lang']).toBe('en')
    expect(get!.headers['X-CSRF-Token']).toBeUndefined()
    expect(post!.headers['X-CSRF-Token']).toBe('tok-123')
    expect(post!.headers['Content-Type']).toBe('application/json')
    expect(post!.body).toEqual({ a: 1 })
    // a bodiless write must still declare JSON: the server requires it
    expect(del!.headers['X-CSRF-Token']).toBe('tok-123')
    expect(del!.headers['Content-Type']).toBe('application/json')
  })
  it('never puts the CSRF token or any credential into web storage', async () => {
    const m = mockFetch({ 'GET /api/state': () => ({ body: { authenticated: true, csrf: 'abc' } }) })
    vi.stubGlobal('fetch', m.impl)
    setCsrf('abc')
    await api.get('/api/state')
    expect(getCsrf()).toBe('abc')
    expect(JSON.stringify({ ...localStorage })).not.toContain('abc')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('abc')
  })
  it('calls fetch with same-origin credentials and no caching', async () => {
    const spy = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', spy)
    await api.get('/api/x')
    expect(spy).toHaveBeenCalledWith('/api/x', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }))
  })
})

describe('responses', () => {
  it('returns parsed JSON, and null for an empty body', async () => {
    const m = mockFetch({ 'GET /a': () => ({ body: { n: 2 } }), 'POST /b': () => ({}) })
    vi.stubGlobal('fetch', m.impl)
    expect(await api.get('/a')).toEqual({ n: 2 })
    expect(await api.post('/b')).toBeNull()
  })
  it('turns the error envelope into an ApiError', async () => {
    const m = mockFetch({ 'POST /api/login': () => ({ status: 429, body: { error: { code: 'rate_limited', message: 'slow down', retry_after: 17 } } }) })
    vi.stubGlobal('fetch', m.impl)
    const e = await api.post('/api/login', { password: 'x' }).catch((x) => x)
    expect(e).toBeInstanceOf(ApiError)
    expect(e).toMatchObject({ status: 429, code: 'rate_limited', message: 'slow down', retryAfter: 17 })
  })
  it('survives a proxy error page without JSON', async () => {
    vi.stubGlobal('fetch', async () => new Response('<html>bad gateway</html>', { status: 502, statusText: 'Bad Gateway' }))
    const e = await api.get('/api/x').catch((x) => x)
    expect(e).toMatchObject({ status: 502, code: 'server' })
  })
  it('reports an unreachable server as a network error', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new TypeError('Failed to fetch')
    })
    const e = await api.get('/api/x').catch((x) => x)
    expect(e).toMatchObject({ code: 'network', status: 0 })
  })
  it('lets an abort through untouched', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new DOMException('aborted', 'AbortError')
    })
    await expect(api.get('/api/x')).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('session loss', () => {
  it('fires when an authenticated call answers 401 unauthenticated', async () => {
    const lost = vi.fn()
    onSessionLost(lost)
    const m = mockFetch({ 'GET /api/nodes': () => ({ status: 401, body: { error: { code: 'unauthenticated', message: 'x' } } }) })
    vi.stubGlobal('fetch', m.impl)
    await api.get('/api/nodes').catch(() => undefined)
    expect(lost).toHaveBeenCalledTimes(1)
  })
  it('does not fire for the login, state and health probes', async () => {
    const lost = vi.fn()
    onSessionLost(lost)
    const body = { error: { code: 'unauthenticated', message: 'x' } }
    const m = mockFetch({ 'POST /api/login': () => ({ status: 401, body }), 'GET /api/state': () => ({ status: 401, body }) })
    vi.stubGlobal('fetch', m.impl)
    await api.post('/api/login', {}).catch(() => undefined)
    await api.get('/api/state').catch(() => undefined)
    expect(lost).not.toHaveBeenCalled()
  })
  it('recognises the re-authentication demand', () => {
    expect(isReauthRequired(new ApiError(403, 'reauth_required', 'x'))).toBe(true)
    expect(isReauthRequired(new ApiError(403, 'forbidden', 'x'))).toBe(false)
    expect(isReauthRequired(new Error('x'))).toBe(false)
  })
})

describe('download', () => {
  it('reads the file name from Content-Disposition', async () => {
    vi.stubGlobal('fetch', async () => new Response('{"a":1}', { headers: { 'Content-Disposition': 'attachment; filename="rout-backup-1.json"' } }))
    const r = await download('/api/system/backup')
    expect(r.filename).toBe('rout-backup-1.json')
    expect(await r.blob.text()).toBe('{"a":1}')
  })
})

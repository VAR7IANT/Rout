import { describe, expect, it, vi } from 'vitest'
import { ApiError, api, needsReauth, transport } from '../core/api'
import { serve } from './harness'

describe('requests', () => {
  it('send the language always and the CSRF token only on writes', async () => {
    transport.setCsrf('tok-123')
    transport.setLang('en')
    const calls = serve({ 'GET /api/x': () => ({ body: { ok: 1 } }), 'POST /api/x': () => ({}), 'DELETE /api/x': () => ({}) })
    await api.get('/api/x')
    await api.post('/api/x', { a: 1 })
    await api.del('/api/x')
    const [get, post, del] = calls
    expect(get.headers['X-Rout-Lang']).toBe('en')
    expect(get.headers['X-CSRF-Token']).toBeUndefined()
    expect(get.headers['Content-Type']).toBeUndefined()
    expect(post.headers['X-CSRF-Token']).toBe('tok-123')
    expect(post.body).toEqual({ a: 1 })
    // A write without a body must still declare JSON: the server rejects it otherwise.
    expect(del.headers['X-CSRF-Token']).toBe('tok-123')
    expect(del.headers['Content-Type']).toBe('application/json')
    expect(del.body).toBeUndefined()
  })
  it('use same-origin credentials and never the HTTP cache', async () => {
    const spy = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', spy)
    await api.get('/api/x')
    expect(spy).toHaveBeenCalledWith('/api/x', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }))
  })
  it('keep the CSRF token out of web storage', () => {
    transport.setCsrf('secret-token')
    expect(transport.csrf()).toBe('secret-token')
    expect(JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })).not.toContain('secret-token')
  })
})

describe('responses', () => {
  it('are parsed JSON, or null when the body is empty', async () => {
    serve({ 'GET /a': () => ({ body: { n: 2 } }), 'POST /b': () => ({}) })
    expect(await api.get('/a')).toEqual({ n: 2 })
    expect(await api.post('/b')).toBeNull()
  })
  it('turn the error envelope into an ApiError', async () => {
    serve({ 'POST /api/login': () => ({ status: 429, body: { error: { code: 'rate_limited', message: 'slow down', retry_after: 17 } } }) })
    const e = await api.post('/api/login', { password: 'x' }).catch((x: unknown) => x)
    expect(e).toBeInstanceOf(ApiError)
    expect(e).toMatchObject({ status: 429, code: 'rate_limited', message: 'slow down', retryAfter: 17 })
  })
  it('call a non-JSON 5xx page a server error', async () => {
    vi.stubGlobal('fetch', async () => new Response('<html>Bad gateway</html>', { status: 502 }))
    expect(await api.get('/api/x').catch((x: unknown) => x)).toMatchObject({ status: 502, code: 'server' })
  })
  it('report an unreachable server as a network error, and pass aborts through', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new TypeError('failed to fetch')
    })
    expect(await api.get('/api/x').catch((x: unknown) => x)).toMatchObject({ status: 0, code: 'network' })
    vi.stubGlobal('fetch', async () => {
      throw new DOMException('aborted', 'AbortError')
    })
    expect(await api.get('/api/x').catch((x: unknown) => x)).toBeInstanceOf(DOMException)
  })
  it('recognise the re-authentication demand', async () => {
    serve({ 'DELETE /api/nodes/1': () => ({ status: 403, body: { error: { code: 'reauth_required', message: 'again' } } }) })
    expect(needsReauth(await api.del('/api/nodes/1').catch((x: unknown) => x))).toBe(true)
    expect(needsReauth(new Error('other'))).toBe(false)
  })
  it('read the file name of a download', async () => {
    serve({ 'GET /api/system/backup': () => ({ body: { a: 1 }, headers: { 'Content-Disposition': 'attachment; filename="rout-full-20261111.json"' } }) })
    expect((await api.file('/api/system/backup')).filename).toBe('rout-full-20261111.json')
  })
})

describe('session expiry', () => {
  const unauthenticated = () => ({ status: 401, body: { error: { code: 'unauthenticated', message: 'sign in' } } })
  it('is announced when an authenticated call is refused', async () => {
    const expired = vi.fn()
    transport.onExpired(expired)
    serve({ 'GET /api/nodes': unauthenticated })
    await api.get('/api/nodes').catch(() => undefined)
    expect(expired).toHaveBeenCalledTimes(1)
  })
  it('is not announced by the calls made before signing in, or by other 401s', async () => {
    const expired = vi.fn()
    transport.onExpired(expired)
    serve({ 'POST /api/login': unauthenticated, 'GET /api/state': unauthenticated, 'GET /api/x': () => ({ status: 401, body: { error: { code: 'invalid_credentials', message: 'no' } } }) })
    await api.post('/api/login', {}).catch(() => undefined)
    await api.get('/api/state').catch(() => undefined)
    await api.get('/api/x').catch(() => undefined)
    expect(expired).not.toHaveBeenCalled()
  })
})

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getCsrf, setCsrf, api } from './api'
import { SessionProvider, useReauth, useSession } from './session'
import { Login } from '../pages/Login'
import { usingPlainHTTP } from '../Shell'
import { mockFetch, renderApp } from '../test-utils'
import { normalizePath, Link, useRouter } from './router'

afterEach(() => {
  vi.unstubAllGlobals()
  setCsrf('')
})

function Probe() {
  const s = useSession()
  return <p>phase:{s.phase}</p>
}

describe('login', () => {
  it('shows the sign-in form to an anonymous visitor and signs in', async () => {
    let authed = false
    const m = mockFetch({
      'GET /api/state': () => ({ body: authed ? { configured: true, authenticated: true, secure: false, csrf: 'csrf-1', version: '0.5.0', session_id: 's' } : { configured: true, authenticated: false, secure: false } }),
      'POST /api/login': (c) => {
        expect(c.body).toEqual({ password: 'correct horse' })
        authed = true
        return { body: { ok: true } }
      },
    })
    vi.stubGlobal('fetch', m.impl)
    renderApp(
      <SessionProvider>
        <Probe />
        <Login />
      </SessionProvider>,
    )
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'correct horse')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(screen.getByText('phase:authenticated')).toBeInTheDocument())
    expect(getCsrf()).toBe('csrf-1')
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('csrf-1')
    expect(JSON.stringify({ ...localStorage })).not.toContain('correct horse')
  })
  it('reports a wrong password and clears the field', async () => {
    const m = mockFetch({
      'GET /api/state': () => ({ body: { configured: true, authenticated: false, secure: false } }),
      'POST /api/login': () => ({ status: 401, body: { error: { code: 'invalid_credentials', message: 'x' } } }),
    })
    vi.stubGlobal('fetch', m.impl)
    renderApp(
      <SessionProvider>
        <Login />
      </SessionProvider>,
    )
    const input = await screen.findByLabelText('Administrator password')
    await userEvent.type(input, 'nope')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Wrong password')).toBeInTheDocument()
    expect(input).toHaveValue('')
  })
  it('tells the administrator to set the password on the server when none exists', async () => {
    const m = mockFetch({ 'GET /api/state': () => ({ body: { configured: false, authenticated: false, secure: false } }) })
    vi.stubGlobal('fetch', m.impl)
    renderApp(
      <SessionProvider>
        <Login />
      </SessionProvider>,
    )
    expect(await screen.findByText('No administrator password has been set')).toBeInTheDocument()
    expect(screen.queryByLabelText('Administrator password')).toBeNull()
    expect(screen.getByText('rout web passwd --generate')).toBeInTheDocument()
  })
  it('shows the retry delay when rate limited', async () => {
    const m = mockFetch({
      'GET /api/state': () => ({ body: { configured: true, authenticated: false, secure: false } }),
      'POST /api/login': () => ({ status: 429, body: { error: { code: 'rate_limited', message: 'x', retry_after: 42 } } }),
    })
    vi.stubGlobal('fetch', m.impl)
    renderApp(
      <SessionProvider>
        <Login />
      </SessionProvider>,
    )
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText(/in 42 s/)).toBeInTheDocument()
  })
  it('falls back to an unreachable state when the service is down', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new TypeError('down')
    })
    renderApp(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    )
    expect(await screen.findByText('phase:unreachable')).toBeInTheDocument()
  })
})

describe('password re-check (reauth guard)', () => {
  function Action() {
    const { guard } = useReauth()
    return <button onClick={() => void guard(() => api.post("/api/secret")).catch(() => undefined)}>reveal</button>
  }
  it('asks for the password once, then retries the refused call', async () => {
    let allowed = false
    const m = mockFetch({
      'POST /api/secret': () => (allowed ? { body: { ok: true } } : { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } }),
      'POST /api/reauth': (c) => {
        expect(c.body).toEqual({ password: 'pw' })
        allowed = true
        return { body: null }
      },
    })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<Action />)
    await userEvent.click(screen.getByRole('button', { name: 'reveal' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: /confirm|verify/i }))
    await waitFor(() => expect(m.calls.filter((c) => c.path === '/api/secret')).toHaveLength(2))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
  it('does not retry when the password prompt is cancelled', async () => {
    const m = mockFetch({ 'POST /api/secret': () => ({ status: 403, body: { error: { code: 'reauth_required', message: 'again' } } }) })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<Action />)
    await userEvent.click(screen.getByRole('button', { name: 'reveal' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(m.calls.filter((c) => c.path === '/api/secret')).toHaveLength(1)
  })
})

describe('router', () => {
  it('normalizes paths', () => {
    expect(normalizePath('/nodes/')).toBe('/nodes')
    expect(normalizePath('')).toBe('/')
    expect(normalizePath('/')).toBe('/')
  })
  it('navigates with the History API and refuses other origins', async () => {
    function Where() {
      const { path, navigate } = useRouter()
      return (
        <>
          <p>at:{path}</p>
          <Link to="/system">go</Link>
          <button onClick={() => navigate('https://evil.example/x')}>away</button>
        </>
      )
    }
    renderApp(<Where />)
    await userEvent.click(screen.getByRole('link', { name: 'go' }))
    expect(screen.getByText('at:/system')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/system')
    await userEvent.click(screen.getByRole('button', { name: 'away' }))
    expect(screen.getByText('at:/system')).toBeInTheDocument()
  })
})

describe('plain HTTP warning', () => {
  it('warns only for http on a non-local host', () => {
    expect(usingPlainHTTP({ protocol: 'http:', hostname: 'panel.example.com' })).toBe(true)
    expect(usingPlainHTTP({ protocol: 'http:', hostname: '127.0.0.1' })).toBe(false)
    expect(usingPlainHTTP({ protocol: 'http:', hostname: 'localhost' })).toBe(false)
    expect(usingPlainHTTP({ protocol: 'https:', hostname: 'panel.example.com' })).toBe(false)
  })
})

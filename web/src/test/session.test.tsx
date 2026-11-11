import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import App from '../app'
import { api, transport } from '../core/api'
import { useAct, useReauth } from '../core/session'
import { mount, sent, serve, type Routes } from './harness'

const guest = { configured: true, authenticated: false, secure: false }
const admin = { configured: true, authenticated: true, secure: true, csrf: 'csrf-1', version: '0.6.1', session_id: 's1' }
// Enough of the dashboard's data for it to render.
const overview = {
  version: '0.6.1',
  system: { cpu_percent: 3, cores: 2, load1: 0.1, mem_total: 8, mem_used: 2, swap_total: 0, swap_used: 0, disk_total: 10, disk_used: 5, net_rx_rate: 0, net_tx_rate: 0, net_rx_total: 0, net_tx_total: 0, uptime_sec: 600, hostname: 'vps', history: [] },
  network: { ipv4: '203.0.113.9', ipv6: '', checking: false, local_ipv4: true, local_ipv6: false },
  counts: { nodes: { total: 0, running: 0, stopped: 0, disabled: 0 }, relays: { total: 0, running: 0, stopped: 0, disabled: 0 }, exits: 0, subscriptions: 0, aggregates: 0, sources: 0, sources_ok: 0, sources_failed: 0, remote_nodes: 0 },
  traffic: { monitoring: false, up: 0, down: 0, total: 0, top: [] },
  certs: [],
  quotas: [],
  alerts: [],
  subscription_server: { enabled: false, running: false, managed: false },
  update: { current: '0.6.1', available: false },
}
const panel: Routes = { 'GET /api/overview': () => ({ body: overview }), 'GET /api/ai': () => ({ status: 500 }), 'GET /api/system/panel': () => ({ status: 500 }) }

describe('signing in', () => {
  it('shows the form to a guest and the panel after the right password', async () => {
    let signedIn = false
    const calls = serve({
      ...panel,
      'GET /api/state': () => ({ body: signedIn ? admin : guest }),
      'POST /api/login': (c) => {
        if ((c.body as { password: string }).password !== 'right') return { status: 401, body: { error: { code: 'invalid_credentials', message: 'bad' } } }
        signedIn = true
        return { body: { csrf: 'csrf-1', session_id: 's1', version: '0.6.1' } }
      },
    })
    render(<App />)
    const field = await screen.findByLabelText(/password/i)
    await userEvent.type(field, 'wrong{Enter}')
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(field).toHaveValue('') // a rejected password is not left in the field

    await userEvent.type(field, 'right{Enter}')
    // Sidebar and phone tab bar are both in the DOM; CSS shows one of them.
    expect(await screen.findAllByRole('navigation', { name: /main navigation/i })).toHaveLength(2)
    expect(transport.csrf()).toBe('csrf-1')
    expect(sent(calls, 'POST', '/api/login')).toHaveLength(2)
  })

  it('explains how to set a password when none exists, without a form', async () => {
    serve({ 'GET /api/state': () => ({ body: { ...guest, configured: false } }) })
    render(<App />)
    expect(await screen.findByText('rout web passwd --generate')).toBeInTheDocument()
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
  })

  it('offers a retry when the service does not answer', async () => {
    let up = false
    serve({ 'GET /api/state': () => (up ? { body: guest } : { status: 502 }) })
    render(<App />)
    const retry = await screen.findByRole('button', { name: /retry/i })
    up = true
    await userEvent.click(retry)
    expect(await screen.findByLabelText(/password/i)).toBeInTheDocument()
  })

  it('drops back to the form, and forgets the token, when the session ends', async () => {
    serve({ ...panel, 'GET /api/state': () => ({ body: admin }), 'GET /api/nodes': () => ({ status: 401, body: { error: { code: 'unauthenticated', message: 'expired' } } }) })
    render(<App />)
    await screen.findAllByRole('navigation', { name: /main navigation/i })
    await api.get('/api/nodes').catch(() => undefined)
    expect(await screen.findByLabelText(/password/i)).toBeInTheDocument()
    expect(transport.csrf()).toBe('')
  })

  it('signs out locally even when the logout call fails', async () => {
    serve({ ...panel, 'GET /api/state': () => ({ body: admin }), 'POST /api/logout': () => ({ status: 500 }) })
    render(<App />)
    await userEvent.click((await screen.findAllByRole('button', { name: /sign out/i }))[0])
    expect(await screen.findByLabelText(/password/i)).toBeInTheDocument()
  })
})

function Dangerous({ onResult }: { onResult: (r: unknown) => void }) {
  const { guard } = useReauth()
  const act = useAct()
  return (
    <button type="button" onClick={async () => onResult(await act(() => guard(() => api.del('/api/nodes/n1'))))}>
      delete
    </button>
  )
}

describe('password re-entry', () => {
  const reauth = { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } }

  it('asks once, then repeats the refused call', async () => {
    let verified = false
    const calls = serve({
      'DELETE /api/nodes/n1': () => (verified ? {} : reauth),
      'POST /api/reauth': () => {
        verified = true
        return {}
      },
    })
    const results: unknown[] = []
    mount(<Dangerous onResult={(r) => results.push(r)} />)
    await userEvent.click(screen.getByRole('button', { name: 'delete' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw{Enter}')
    await waitFor(() => expect(results).toEqual([null]))
    expect(sent(calls, 'DELETE', '/api/nodes/n1')).toHaveLength(2)
    expect(sent(calls, 'POST', '/api/reauth')[0].body).toEqual({ password: 'pw' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('stops quietly when the prompt is dismissed', async () => {
    const calls = serve({ 'DELETE /api/nodes/n1': () => reauth })
    const results: unknown[] = []
    mount(<Dangerous onResult={(r) => results.push(r)} />)
    await userEvent.click(screen.getByRole('button', { name: 'delete' }))
    await screen.findByRole('dialog')
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(results).toEqual([undefined]))
    expect(sent(calls, 'DELETE', '/api/nodes/n1')).toHaveLength(1)
    expect(screen.queryByRole('status')?.textContent ?? '').toBe('') // no error line for a cancel
  })

  it('keeps the prompt open with the reason when the password is wrong', async () => {
    serve({ 'DELETE /api/nodes/n1': () => reauth, 'POST /api/reauth': () => ({ status: 401, body: { error: { code: 'invalid_credentials', message: 'Wrong password' } } }) })
    mount(<Dangerous onResult={() => undefined} />)
    await userEvent.click(screen.getByRole('button', { name: 'delete' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'nope{Enter}')
    expect(await screen.findByText('Wrong password')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})

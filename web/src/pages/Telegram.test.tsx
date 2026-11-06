import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { TelegramBindRequest, TelegramProbe, TelegramStatus } from '../lib/types'
import { mockFetch, renderApp, type Call } from '../test-utils'
import { TelegramCard } from './Telegram'

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  window.localStorage.clear()
  window.sessionStorage.clear()
})
beforeEach(() => {
  window.localStorage.clear()
  window.sessionStorage.clear()
})

const TOKEN = '123456789:AAHsecretTOKENvalue_for-tests01'
const FP = 'AB12 CD34 EF56 7890 AB12 CD34 EF56 7890'
const HUB_FP = '1111 2222 3333 4444 5555 6666 7777 8888'
const iso = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60000).toISOString()

const base = {
  service: { installed: true, running: true, managed: true },
  servers: [],
  pending: [],
  audit: [],
}

const unbound: TelegramStatus = { ...base, bound: false, connection: { state: 'unbound' } }

const hubStatus: TelegramStatus = {
  ...base,
  bound: true,
  role: 'hub',
  server_id: 'a1b2c3d4',
  server_name: 'tokyo-1',
  bot_username: 'rout_manage_bot',
  chat_id_masked: '••••3456',
  fingerprint: FP,
  connection: { state: 'connected', detail: 'Polling Telegram', last_ok: iso(2) },
  hub: { endpoints: ['203.0.113.7:9443', '[2001:db8:85a3:0000:0000:8a2e:0370:7334]:9443'], fingerprint: FP, multi_server: true, port: 9443 },
  servers: [
    { id: 'a1b2c3d4', name: 'tokyo-1', self: true, online: true, last_seen: iso(0), fingerprint: FP, version: '0.6.0', ai_enabled: true, exit_name: 'US-socks' },
    { id: 'e5f6a7b8', name: 'frankfurt-2', self: false, online: false, last_seen: iso(90), fingerprint: '9999 8888 7777 6666 5555 4444 3333 2222', ai_enabled: false },
  ],
  pending: [{ id: 'p1', name: 'sydney-3', fingerprint: '0A0A 0B0B 0C0C 0D0D 0E0E 0F0F 1010 2020', requested_at: iso(3) }],
  audit: ['2026-11-06T10:00:00Z bound as hub', '2026-11-06T10:05:00Z frankfurt-2 approved'],
}

const agentPending: TelegramStatus = {
  ...base,
  bound: true,
  role: 'agent',
  server_id: 'c0ffee01',
  server_name: 'osaka-1',
  bot_username: 'rout_manage_bot',
  chat_id_masked: '••••3456',
  fingerprint: FP,
  connection: { state: 'pending', detail: 'Waiting for the hub to approve this server' },
  follows: { endpoints: ['203.0.113.7:9443'], fingerprint: HUB_FP },
}

const probeHub: TelegramProbe = { bot_username: 'rout_manage_bot', suggested_name: 'tokyo-1', webhook_active: false, hub: { found: false } }
const probeAgent: TelegramProbe = {
  bot_username: 'rout_manage_bot',
  suggested_name: 'osaka-1',
  webhook_active: false,
  hub: { found: true, endpoints: ['203.0.113.7:9443', '[2001:db8::1]:9443'], fingerprint: HUB_FP, hub_name: 'tokyo-1' },
}

function setup(routes: Parameters<typeof mockFetch>[0], initial: TelegramStatus = unbound) {
  const m = mockFetch({ 'GET /api/telegram': () => ({ body: initial }), ...routes })
  vi.stubGlobal('fetch', m.impl)
  const view = renderApp(<TelegramCard />)
  return { ...m, ...view }
}

const callsTo = (m: { calls: Call[] }, method: string, path: string) => m.calls.filter((c) => c.method === method && c.path === path)

async function openWizard() {
  await userEvent.click(await screen.findByRole('button', { name: 'Bind Telegram Bot' }))
}
async function fillCredentials(token = TOKEN, chat = '123456789') {
  await userEvent.type(screen.getByLabelText(/^Bot Token/), token)
  await userEvent.type(screen.getByLabelText(/^Chat ID/), chat)
}

describe('TelegramCard — not bound', () => {
  it('explains what it does and offers the bind wizard', async () => {
    setup({})
    expect(await screen.findByRole('heading', { name: 'Telegram Bot' })).toBeInTheDocument()
    expect(screen.getByText('Not bound')).toBeInTheDocument()
    expect(screen.getByText(/Rout never changes firewalls/)).toBeInTheDocument()
    expect(screen.getByText(/never shown again/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Bind Telegram Bot' })).toBeEnabled()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows why the status cannot be read and lets the user retry', async () => {
    const m = setup({ 'GET /api/telegram': () => ({ status: 500, body: { error: { code: 'server', message: 'boom' } } }) })
    expect(await screen.findByText('Could not read the Telegram status')).toBeInTheDocument()
    expect(screen.getByText(/temporarily unavailable/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(callsTo(m, 'GET', '/api/telegram').length).toBe(2))
  })
})

describe('bind wizard', () => {
  it('keeps the token in a password field and probes with {token, chat_id}', async () => {
    const m = setup({ 'POST /api/telegram/probe': () => ({ body: probeHub }) })
    await openWizard()
    const token = screen.getByLabelText(/^Bot Token/)
    expect(token).toHaveAttribute('type', 'password')
    expect(token).toHaveAttribute('autocomplete', 'off')
    expect(token).toHaveAttribute('spellcheck', 'false')
    expect(screen.getByLabelText(/^Chat ID/)).toHaveAttribute('inputmode', 'numeric')
    const check = screen.getByRole('button', { name: 'Check' })
    expect(check).toBeDisabled()
    await fillCredentials()
    expect(check).toBeEnabled()
    await userEvent.click(check)
    expect(await screen.findByText('@rout_manage_bot')).toBeInTheDocument()
    expect(callsTo(m, 'POST', '/api/telegram/probe')[0]!.body).toEqual({ token: TOKEN, chat_id: '123456789' })
  })

  it('rejects group and channel ids before calling the server', async () => {
    const m = setup({})
    await openWizard()
    await fillCredentials(TOKEN, '-1001234567890')
    expect(screen.getByText(/Groups and channels \(negative IDs\) are not supported/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Check' })).toBeDisabled()
    expect(callsTo(m, 'POST', '/api/telegram/probe')).toHaveLength(0)
  })

  it('shows the server message when the probe fails and stays on the first step', async () => {
    setup({ 'POST /api/telegram/probe': () => ({ status: 400, body: { error: { code: 'bad_token', message: `Telegram rejected the token ${TOKEN}` } } }) })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Telegram rejected the token')
    // even a server that echoes the token cannot put it on the page
    expect(alert).not.toHaveTextContent(TOKEN)
    expect(screen.getByLabelText(/^Bot Token/)).toBeInTheDocument()
  })

  it('joins an existing hub as an agent only after the fingerprint is confirmed', async () => {
    const m = setup({
      'POST /api/telegram/probe': () => ({ body: probeAgent }),
      'POST /api/telegram/bind': () => ({ body: agentPending }),
    })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/will join it as an agent/)).toBeInTheDocument()
    expect(screen.getByText(HUB_FP)).toBeInTheDocument()
    expect(screen.getByText('[2001:db8::1]:9443')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7:9443')).toBeInTheDocument()
    expect(screen.getByLabelText(/^Server name/)).toHaveValue('osaka-1')
    // no hub-only options for an agent
    expect(screen.queryByText('Allow other servers to join')).toBeNull()

    const bind = screen.getByRole('button', { name: 'Bind' })
    expect(bind).toBeDisabled()
    const verified = screen.getByRole('checkbox', { name: /I verified the fingerprint/ })
    await userEvent.click(verified)
    expect(bind).toBeEnabled()
    await userEvent.click(verified)
    expect(bind).toBeDisabled()
    await userEvent.click(verified)

    await userEvent.click(bind)
    await waitFor(() => expect(callsTo(m, 'POST', '/api/telegram/bind')).toHaveLength(1))
    expect(callsTo(m, 'POST', '/api/telegram/bind')[0]!.body).toEqual({ token: TOKEN, chat_id: '123456789', server_name: 'osaka-1', role: 'agent', trust_hub_fp: HUB_FP })

    // the wizard is gone and the agent is told how to get approved
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText(/Tap “✅ Allow” in the Telegram chat/)).toBeInTheDocument()
    expect(screen.getByText('Agent')).toBeInTheDocument()
    expect(screen.getByText('Waiting for approval', { selector: '.badge' })).toBeInTheDocument()
  })

  it('becomes the hub when none exists, sending multi_server and delete_webhook', async () => {
    const m = setup({
      'POST /api/telegram/probe': () => ({ body: { ...probeHub, webhook_active: true } }),
      'POST /api/telegram/bind': () => ({ body: hubStatus }),
    })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/this server becomes the control hub/)).toBeInTheDocument()
    expect(screen.getByText(/Rout never changes firewalls\. No third-party service is used/)).toBeInTheDocument()
    const multi = screen.getByRole('checkbox', { name: /Allow other servers to join/ })
    expect(multi).toBeChecked()

    // a webhook has to be deleted before polling can start
    const bind = screen.getByRole('button', { name: 'Bind' })
    expect(bind).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /Delete the existing webhook/ }))
    expect(bind).toBeEnabled()

    await userEvent.clear(screen.getByLabelText(/^Server name/))
    expect(bind).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/^Server name/), 'tokyo-1')
    await userEvent.click(bind)
    await waitFor(() => expect(callsTo(m, 'POST', '/api/telegram/bind')).toHaveLength(1))
    const body = callsTo(m, 'POST', '/api/telegram/bind')[0]!.body as TelegramBindRequest
    expect(body).toEqual({ token: TOKEN, chat_id: '123456789', server_name: 'tokyo-1', role: 'hub', multi_server: true, delete_webhook: true })
    expect(body.trust_hub_fp).toBeUndefined()
    expect(await screen.findByText('@rout_manage_bot')).toBeInTheDocument()
    expect(screen.getByText('Hub')).toBeInTheDocument()
  })

  it('omits delete_webhook when there is none and honours turning other servers off', async () => {
    const m = setup({ 'POST /api/telegram/probe': () => ({ body: probeHub }), 'POST /api/telegram/bind': () => ({ body: hubStatus }) })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await screen.findByText(/this server becomes the control hub/)
    expect(screen.queryByText(/Delete the existing webhook/)).toBeNull()
    await userEvent.click(screen.getByRole('checkbox', { name: /Allow other servers to join/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Bind' }))
    await waitFor(() => expect(callsTo(m, 'POST', '/api/telegram/bind')).toHaveLength(1))
    expect(callsTo(m, 'POST', '/api/telegram/bind')[0]!.body).toEqual({ token: TOKEN, chat_id: '123456789', server_name: 'tokyo-1', role: 'hub', multi_server: false })
  })

  it('goes back to the first step and probes again', async () => {
    const m = setup({ 'POST /api/telegram/probe': () => ({ body: probeHub }) })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await screen.findByText('@rout_manage_bot')
    await userEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(screen.getByLabelText(/^Bot Token/)).toHaveValue(TOKEN)
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await screen.findByText('@rout_manage_bot')
    expect(callsTo(m, 'POST', '/api/telegram/probe')).toHaveLength(2)
  })

  it('shows the error when binding fails and keeps the wizard open', async () => {
    setup({
      'POST /api/telegram/probe': () => ({ body: probeHub }),
      'POST /api/telegram/bind': () => ({ status: 409, body: { error: { code: 'conflict', message: 'Port 9443 is already in use' } } }),
    })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await screen.findByText('@rout_manage_bot')
    await userEvent.click(screen.getByRole('button', { name: 'Bind' }))
    expect(await screen.findByText('Port 9443 is already in use')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('never leaves the token in the page or in browser storage', async () => {
    let stored = ''
    const m = setup({
      'POST /api/telegram/probe': () => ({ body: probeHub }),
      'POST /api/telegram/bind': () => ({ body: hubStatus }),
    })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await screen.findByText('@rout_manage_bot')
    await userEvent.click(screen.getByRole('button', { name: 'Bind' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(callsTo(m, 'POST', '/api/telegram/bind')).toHaveLength(1)
    await screen.findByText('Hub')

    expect(document.body.innerHTML).not.toContain(TOKEN)
    expect(document.body.textContent).not.toContain(TOKEN)
    for (const store of [window.localStorage, window.sessionStorage]) {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i)!
        stored += k + store.getItem(k)
      }
    }
    expect(stored).not.toContain(TOKEN)
    expect(stored).not.toContain('123456789:')
    // only the masked chat id is ever shown
    expect(screen.getByText('••••3456')).toBeInTheDocument()
  })

  it('asks for the password again when the server requires it and then continues', async () => {
    let probes = 0
    const m = setup({
      'POST /api/telegram/probe': () => {
        probes++
        return probes === 1 ? { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } } : { body: probeHub }
      },
      'POST /api/reauth': () => ({ body: { ok: true } }),
    })
    await openWizard()
    await fillCredentials()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: 'Verify and continue' }))
    expect(await screen.findByText('@rout_manage_bot')).toBeInTheDocument()
    expect(probes).toBe(2)
    expect(callsTo(m, 'POST', '/api/reauth')[0]!.body).toEqual({ password: 'pw' })
  })
})

describe('bound hub', () => {
  it('shows the identity, the servers and the servers waiting for approval', async () => {
    setup({}, hubStatus)
    expect(await screen.findByText('@rout_manage_bot')).toBeInTheDocument()
    expect(screen.getByText('Hub')).toBeInTheDocument()
    expect(screen.getByText('Connected', { selector: '.badge' })).toBeInTheDocument()
    expect(screen.getByText('Polling Telegram')).toBeInTheDocument()
    expect(screen.getByText('••••3456')).toBeInTheDocument()
    expect(screen.getByText('[2001:db8:85a3:0000:0000:8a2e:0370:7334]:9443')).toBeInTheDocument()
    expect(screen.getByText('9443')).toBeInTheDocument()

    // servers: the hub itself is marked and cannot be revoked
    const table = screen.getByRole('table', { name: 'Servers managed through Telegram' })
    expect(within(table).getByText('This server')).toBeInTheDocument()
    expect(within(table).getByText('frankfurt-2')).toBeInTheDocument()
    expect(within(table).getByText('Online')).toBeInTheDocument()
    expect(within(table).getByText('Offline')).toBeInTheDocument()
    expect(within(table).getByText('Exit: US-socks')).toBeInTheDocument()
    expect(within(table).getByText('9999 8888 7777 6666 5555 4444 3333 2222')).toBeInTheDocument()
    expect(within(table).getAllByRole('button', { name: /^Revoke/ })).toHaveLength(1)

    // pending
    expect(screen.getByText('sydney-3')).toBeInTheDocument()
    expect(screen.getByText('0A0A 0B0B 0C0C 0D0D 0E0E 0F0F 1010 2020')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Approve sydney-3' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reject sydney-3' })).toBeInTheDocument()
  })

  it('approves a waiting server', async () => {
    let asked = 0
    const m = setup(
      {
        'POST /api/telegram/pending/p1/approve': () => {
          asked++
          return asked === 1 ? { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } } : { body: { ...hubStatus, pending: [] } }
        },
        'POST /api/reauth': () => ({ body: { ok: true } }),
      },
      hubStatus,
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Approve sydney-3' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: 'Verify and continue' }))
    await waitFor(() => expect(screen.queryByText('sydney-3')).toBeNull())
    expect(callsTo(m, 'POST', '/api/telegram/pending/p1/approve')).toHaveLength(2)
    expect(await screen.findByText('sydney-3 approved')).toBeInTheDocument()
  })

  it('rejects a waiting server', async () => {
    const m = setup({ 'POST /api/telegram/pending/p1/reject': () => ({ body: { ...hubStatus, pending: [] } }) }, hubStatus)
    await userEvent.click(await screen.findByRole('button', { name: 'Reject sydney-3' }))
    await waitFor(() => expect(screen.queryByText('Waiting for approval')).toBeNull())
    expect(callsTo(m, 'POST', '/api/telegram/pending/p1/reject')).toHaveLength(1)
    expect(await screen.findByText('sydney-3 rejected')).toBeInTheDocument()
  })

  it('revokes a server only after a confirmation', async () => {
    const m = setup({ 'DELETE /api/telegram/servers/e5f6a7b8': () => ({ body: { ...hubStatus, servers: hubStatus.servers.filter((x) => x.self) } }) }, hubStatus)
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke frankfurt-2' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Revoke frankfurt-2?')).toBeInTheDocument()
    expect(callsTo(m, 'DELETE', '/api/telegram/servers/e5f6a7b8')).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(callsTo(m, 'DELETE', '/api/telegram/servers/e5f6a7b8')).toHaveLength(1))
    await waitFor(() => expect(screen.queryByText('frankfurt-2')).toBeNull())
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('does not revoke when the confirmation is cancelled', async () => {
    const m = setup({}, hubStatus)
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke frankfurt-2' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(m.calls.some((c) => c.method === 'DELETE')).toBe(false)
  })

  it('lists the activity in a collapsible section', async () => {
    setup({}, hubStatus)
    const summary = await screen.findByText('Activity (2)')
    const details = summary.closest('details')!
    expect(details).not.toHaveAttribute('open')
    expect(within(details).getByText('2026-11-06T10:05:00Z frankfurt-2 approved')).toBeInTheDocument()
  })

  it('warns when the background service is stopped or not managed', async () => {
    setup({}, { ...hubStatus, service: { installed: true, running: false, managed: false } })
    expect(await screen.findByText('The Telegram service is not running')).toBeInTheDocument()
    expect(screen.getByText('The Telegram service is not managed by the system')).toBeInTheDocument()
  })

  it('renders the connection test steps with their levels', async () => {
    const m = setup(
      {
        'POST /api/telegram/test': () => ({
          body: {
            ok: false,
            steps: [
              { level: 'ok', text: 'Telegram API reachable' },
              { level: 'warn', text: 'Webhook is set' },
              { level: 'fail', text: 'Hub port 9443 not reachable from outside' },
              { level: 'info', text: 'Fingerprint AB12' },
            ],
          },
        }),
      },
      hubStatus,
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText('The connection test failed')).toBeInTheDocument()
    const item = screen.getByText('Hub port 9443 not reachable from outside').closest('li')!
    expect(item).toHaveClass('diag-fail')
    expect(screen.getByText('Telegram API reachable').closest('li')).toHaveClass('diag-ok')
    expect(screen.getByText('Webhook is set').closest('li')).toHaveClass('diag-warn')
    expect(screen.getByText('Fingerprint AB12').closest('li')).toHaveClass('diag-info')
    expect(callsTo(m, 'POST', '/api/telegram/test')).toHaveLength(1)
    // the test is not behind the password prompt
    expect(m.calls.some((c) => c.path === '/api/reauth')).toBe(false)
  })

  it('reports a failed test call', async () => {
    setup({ 'POST /api/telegram/test': () => ({ status: 502, body: { error: { code: 'upstream', message: 'Telegram did not answer' } } }) }, hubStatus)
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }))
    expect(await screen.findByText('Telegram did not answer')).toBeInTheDocument()
  })
})

describe('bound agent', () => {
  it('shows the hub it follows and what to do while waiting for approval', async () => {
    setup({}, agentPending)
    expect(await screen.findByText('Agent')).toBeInTheDocument()
    expect(screen.getByText('Waiting for approval', { selector: '.badge' })).toBeInTheDocument()
    expect(screen.getByText(/approve it in the hub’s panel/)).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7:9443')).toBeInTheDocument()
    expect(screen.getByText(HUB_FP)).toBeInTheDocument()
    expect(screen.queryByText('Servers')).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  it('says so when the hub revoked this server', async () => {
    setup({}, { ...agentPending, connection: { state: 'revoked', detail: 'The hub refused this certificate' } })
    expect(await screen.findByText(/The hub has revoked this server/)).toBeInTheDocument()
    expect(screen.getByText('The hub refused this certificate')).toBeInTheDocument()
  })
})

describe('edit', () => {
  async function openEdit() {
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    return screen.findByRole('dialog')
  }

  it('prefills the name and sends only what changed', async () => {
    const m = setup({ 'PATCH /api/telegram': () => ({ body: { ...hubStatus, server_name: 'tokyo-main' } }) }, hubStatus)
    const dialog = await openEdit()
    const save = within(dialog).getByRole('button', { name: 'Save' })
    const name = within(dialog).getByLabelText(/^Server name/)
    expect(name).toHaveValue('tokyo-1')
    expect(within(dialog).getByLabelText(/^Replace bot token/)).toHaveValue('')
    expect(within(dialog).getByLabelText(/^Replace bot token/)).toHaveAttribute('type', 'password')
    expect(save).toBeDisabled()
    await userEvent.clear(name)
    await userEvent.type(name, 'tokyo-main')
    expect(save).toBeEnabled()
    await userEvent.click(save)
    await waitFor(() => expect(callsTo(m, 'PATCH', '/api/telegram')).toHaveLength(1))
    expect(callsTo(m, 'PATCH', '/api/telegram')[0]!.body).toEqual({ server_name: 'tokyo-main' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText('tokyo-main')).toBeInTheDocument()
  })

  it('sends only multi_server when only the toggle changed', async () => {
    const m = setup({ 'PATCH /api/telegram': () => ({ body: { ...hubStatus, hub: { ...hubStatus.hub!, multi_server: false } } }) }, hubStatus)
    const dialog = await openEdit()
    const toggle = within(dialog).getByRole('checkbox', { name: /Allow other servers to join/ })
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    expect(within(dialog).getByText(/other servers can no longer connect to this hub/)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(callsTo(m, 'PATCH', '/api/telegram')).toHaveLength(1))
    expect(callsTo(m, 'PATCH', '/api/telegram')[0]!.body).toEqual({ multi_server: false })
  })

  it('replaces the token and chat id without sending the unchanged fields and drops the token afterwards', async () => {
    const m = setup({ 'PATCH /api/telegram': () => ({ body: { ...hubStatus, chat_id_masked: '••••7777' } }) }, hubStatus)
    const dialog = await openEdit()
    await userEvent.type(within(dialog).getByLabelText(/^Replace bot token/), TOKEN)
    await userEvent.type(within(dialog).getByLabelText(/^Replace chat ID/), '987654321')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(callsTo(m, 'PATCH', '/api/telegram')).toHaveLength(1))
    expect(callsTo(m, 'PATCH', '/api/telegram')[0]!.body).toEqual({ token: TOKEN, chat_id: '987654321' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText('••••7777')).toBeInTheDocument()
    expect(document.body.innerHTML).not.toContain(TOKEN)
  })

  it('shows the server message when saving fails and keeps the dialog', async () => {
    setup({ 'PATCH /api/telegram': () => ({ status: 400, body: { error: { code: 'bad_request', message: 'The bot cannot write to that chat' } } }) }, hubStatus)
    const dialog = await openEdit()
    await userEvent.type(within(dialog).getByLabelText(/^Replace chat ID/), '5')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByText('The bot cannot write to that chat')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('hides the multi-server switch for an agent', async () => {
    setup({}, agentPending)
    const dialog = await openEdit()
    expect(within(dialog).queryByRole('checkbox')).toBeNull()
  })
})

describe('unbind', () => {
  it('asks first, then unbinds and shows the not-bound view', async () => {
    let bound = true
    const m = setup(
      {
        'GET /api/telegram': () => ({ body: bound ? hubStatus : unbound }),
        'POST /api/telegram/unbind': () => {
          bound = false
          return { body: { ok: true } }
        },
      },
      hubStatus,
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Unbind' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Unbind the Telegram Bot?')).toBeInTheDocument()
    expect(within(dialog).getByText(/1 servers that joined will lose their connection/)).toBeInTheDocument()
    expect(callsTo(m, 'POST', '/api/telegram/unbind')).toHaveLength(0)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Unbind' }))
    await waitFor(() => expect(callsTo(m, 'POST', '/api/telegram/unbind')).toHaveLength(1))
    expect(await screen.findByRole('button', { name: 'Bind Telegram Bot' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows the error and keeps everything when unbinding fails', async () => {
    setup({ 'POST /api/telegram/unbind': () => ({ status: 500, body: { error: { code: 'server', message: 'x' } } }) }, hubStatus)
    await userEvent.click(await screen.findByRole('button', { name: 'Unbind' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Unbind' }))
    expect(await screen.findByText(/temporarily unavailable/)).toBeInTheDocument()
    expect(screen.getByText('@rout_manage_bot')).toBeInTheDocument()
  })
})

describe('polling', () => {
  it('refreshes every 5 seconds and stops when the card is unmounted', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const m = setup({}, hubStatus)
    await screen.findByText('@rout_manage_bot')
    const gets = () => callsTo(m, 'GET', '/api/telegram').length
    expect(gets()).toBe(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(gets()).toBe(2)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(gets()).toBe(3)

    m.unmount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000)
    })
    expect(gets()).toBe(3)
  })

  it('shows a new waiting server that appears on a later poll', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let current: TelegramStatus = { ...hubStatus, pending: [] }
    setup({ 'GET /api/telegram': () => ({ body: current }) }, hubStatus)
    await screen.findByText('@rout_manage_bot')
    expect(screen.queryByText('sydney-3')).toBeNull()
    current = hubStatus
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(await screen.findByText('sydney-3')).toBeInTheDocument()
  })

  it('keeps the last good status and says so when a refresh fails', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let down = false
    setup({ 'GET /api/telegram': () => (down ? { status: 500, body: { error: { code: 'server', message: 'x' } } } : { body: hubStatus }) }, hubStatus)
    await screen.findByText('@rout_manage_bot')
    down = true
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })
    expect(await screen.findByText(/Could not refresh the status/)).toBeInTheDocument()
    expect(screen.getByText('@rout_manage_bot')).toBeInTheDocument()
  })
})

import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AIView, DiagResult, ExitView, RelayView } from '../lib/types'
import { mockFetch, renderApp } from '../test-utils'
import { AIPage, observedExitIPs } from './AI'

afterEach(() => vi.unstubAllGlobals())

const exitBase: ExitView = {
  id: 'x1',
  name: 'US-socks',
  kind: 'classic',
  protocol: 'socks5',
  label: 'SOCKS5',
  host: '198.51.100.20',
  port: 1080,
  has_auth: true,
  transport: 'tcp',
  nodes: [],
  node_ids: [],
  ai: false,
  refs: 0,
  path: ['Local inbound', 'SOCKS5 198.51.100.20:1080', 'Internet'],
  ai_usable: true,
}

const relay = {
  id: 'r1',
  name: 'CA-hop',
  kind: 'relay',
  protocol: 'tcp',
  label: 'TCP',
  enabled: true,
  state: 'running',
  listen: '0.0.0.0',
  port: 20001,
  public_host: '203.0.113.5',
  public_port: 20001,
  networks: ['tcp'],
  subscriptions: [],
  warnings: [],
  has_link: false,
  mode: 'remote',
  target: '198.51.100.20:1080',
  transport: 'tcp',
  engine: 'gost',
  path: [],
  chain_exits: [],
  ai_chain: false,
} as RelayView

function view(over: Partial<AIView> = {}): AIView {
  return {
    enabled: false,
    rule_set: 2,
    rule_set_available: 2,
    problems: [],
    nodes: [
      { id: 'n1', name: 'reality-hk', protocol: 'vless', bound: false, eligible: true, running: 'Running', in_sync: true, exit: 'direct' },
      { id: 'n2', name: 'hy2-jp', protocol: 'hysteria2', bound: true, eligible: true, running: 'Running', in_sync: true, exit: 'JP-out' },
      { id: 'n3', name: 'ss-old', protocol: 'shadowsocks', bound: false, eligible: false, running: 'Stopped', in_sync: true, note: 'unsupported transport', exit: 'direct' },
    ],
    exits: [exitBase, { ...exitBase, id: 'x2', name: 'Broken', ai_usable: false, ai_problem: 'loops back to this server' }],
    relays: [relay],
    services: [{ name: 'OpenAI', suffixes: ['openai.com', 'chatgpt.com'] }],
    limits: ['Only checked inbound nodes take part'],
    ...over,
  }
}

function setup(routes: Parameters<typeof mockFetch>[0] = {}, v = view()) {
  const m = mockFetch({ 'GET /api/ai': () => ({ body: v }), ...routes })
  vi.stubGlobal('fetch', m.impl)
  renderApp(<AIPage />)
  return m
}

describe('AIPage', () => {
  it('lists the inbound nodes with what the server reports', async () => {
    setup()
    const alpha = await screen.findByRole('checkbox', { name: /reality-hk/ })
    expect(alpha).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /hy2-jp/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /ss-old/ })).toBeDisabled()
    expect(screen.getByText(/unsupported transport/)).toBeInTheDocument()
    // the unusable exit cannot be chosen and says why
    expect(screen.getByRole('radio', { name: /Broken/ })).toBeDisabled()
    expect(screen.getByText('loops back to this server')).toBeInTheDocument()
  })

  it('saves the checked nodes with PUT /api/ai/bindings', async () => {
    const m = setup({ 'PUT /api/ai/bindings': (c) => ({ body: view({ nodes: view().nodes.map((n) => ({ ...n, bound: (c.body as { ids: string[] }).ids.includes(n.id) })) }) }) })
    const save = (await screen.findAllByRole('button', { name: 'Save' }))[0]!
    expect(save).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /reality-hk/ }))
    await userEvent.click(screen.getByRole('checkbox', { name: /hy2-jp/ }))
    expect(save).toBeEnabled()
    await userEvent.click(save)
    await waitFor(() => expect(m.calls.some((c) => c.method === 'PUT' && c.path === '/api/ai/bindings')).toBe(true))
    expect(m.calls.find((c) => c.path === '/api/ai/bindings')!.body).toEqual({ ids: ['n1'] })
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /reality-hk/ })).toBeChecked())
  })

  it('creates a relay chain exit and makes it the AI exit', async () => {
    const chain: ExitView = { ...exitBase, id: 'c1', name: 'Chain-CA', kind: 'chain', via_relay: 'r1', via_relay_name: 'CA-hop' }
    const m = setup({
      'POST /api/exits/chain': () => ({ body: { exit: chain } }),
      'PUT /api/ai/exit': () => ({ body: view({ exit_id: 'c1', exit: chain, exits: [...view().exits, chain] }) }),
    })
    await userEvent.click(await screen.findByRole('radio', { name: 'Via a relay' }))
    // SOCKS5 is the default end service for a relay that has no node link: the warning shows
    expect(screen.getByText('Unencrypted proxy')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/^Username/), 'alice')
    const pass = screen.getByLabelText(/^Password/)
    expect(pass).toHaveAttribute('type', 'password')
    await userEvent.type(pass, 's3cret')
    await userEvent.click(screen.getByRole('button', { name: 'Create and use as AI exit' }))
    await waitFor(() => expect(m.calls.some((c) => c.path === '/api/ai/exit')).toBe(true))
    expect(m.calls.find((c) => c.path === '/api/exits/chain')!.body).toEqual({ via_relay: 'r1', protocol: 'socks5', username: 'alice', password: 's3cret' })
    expect(m.calls.find((c) => c.path === '/api/ai/exit')!.body).toEqual({ exit_id: 'c1' })
  })

  it('creates a chain through another server with the end proxy given', async () => {
    const m = setup({
      'POST /api/exits/chain': () => ({ body: { exit: { ...exitBase, id: 'c2', kind: 'chain' } } }),
      'PUT /api/ai/exit': () => ({ body: view({ exit_id: 'c2' }) }),
    })
    await userEvent.click(await screen.findByRole('radio', { name: 'Via another server' }))
    const create = screen.getByRole('button', { name: 'Create and use as AI exit' })
    expect(create).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/^Forwarder/), '[[2001:db8::7]:20001')
    await userEvent.click(screen.getByRole('radio', { name: 'HTTPS CONNECT' }))
    expect(screen.queryByText('Unencrypted proxy')).toBeNull()
    await userEvent.type(screen.getByLabelText(/^Host/), 'proxy.example.net')
    await userEvent.type(screen.getByLabelText(/^Port/), '8443')
    await userEvent.click(create)
    await waitFor(() => expect(m.calls.some((c) => c.path === '/api/ai/exit')).toBe(true))
    expect(m.calls.find((c) => c.path === '/api/exits/chain')!.body).toEqual({ via_address: '[2001:db8::7]:20001', protocol: 'https', host: 'proxy.example.net', port: 8443 })
  })

  it('runs the end-to-end test and highlights the observed exit IP', async () => {
    const result: DiagResult = {
      ok: true,
      steps: [
        { layer: 1, layer_name: 'Inbound', level: 'ok', text: 'Inbound hy2-jp OK' },
        { layer: 6, layer_name: 'Real request', level: 'ok', text: 'Exit IPv4: 198.51.100.20' },
        { layer: 6, layer_name: 'Real request', level: 'ok', text: 'AI exit chain usable' },
      ],
    }
    const m = setup({ 'POST /api/ai/test': () => ({ body: result }) }, view({ exit_id: 'x1', exit: exitBase }))
    await userEvent.click(await screen.findByRole('button', { name: 'Run test' }))
    const box = await screen.findByText('Observed exit IP')
    expect(within(box.parentElement!).getByText('198.51.100.20')).toBeInTheDocument()
    expect(screen.getByText('AI exit chain usable')).toBeInTheDocument()
    expect(m.calls.some((c) => c.method === 'POST' && c.path === '/api/ai/test')).toBe(true)
  })

  it('reports a busy test runner instead of failing silently', async () => {
    setup({ 'POST /api/ai/test': () => ({ status: 429, body: { error: { code: 'busy', message: 'busy', retry_after: 5 } } }) }, view({ exit_id: 'x1', exit: exitBase }))
    await userEvent.click(await screen.findByRole('button', { name: 'Run test' }))
    expect(await screen.findByText(/Another test is running/)).toBeInTheDocument()
  })

  it('labels the route simulation as a simulation', async () => {
    const m = setup({ 'POST /api/ai/simulate': () => ({ body: { host: 'chat.openai.com', nodes: [{ id: 'n2', name: 'hy2-jp', route: 'ai' }] } }) })
    expect(await screen.findByText('Rule simulation')).toBeInTheDocument()
    expect(screen.getByLabelText('Domain to simulate')).toHaveValue('chat.openai.com')
    await userEvent.click(screen.getByRole('button', { name: 'Simulate' }))
    const badge = await screen.findByText('Simulated')
    expect(within(badge.closest('.stack') as HTMLElement).getByText('AI exit')).toBeInTheDocument()
    expect(m.calls.find((c) => c.path === '/api/ai/simulate')!.body).toEqual({ host: 'chat.openai.com' })
  })
})

describe('observedExitIPs', () => {
  it('picks IPv4 and IPv6 addresses from the real-request layer only', () => {
    const r: DiagResult = {
      ok: true,
      steps: [
        { layer: 3, layer_name: 'x', level: 'ok', text: 'Relay target 10.0.0.1:1080' },
        { layer: 6, layer_name: 'x', level: 'ok', text: '出口 IPv4：203.0.113.9' },
        { layer: 6, layer_name: 'x', level: 'ok', text: '出口 IPv6：2001:db8:85a3::8a2e:370:7334' },
        { layer: 6, layer_name: 'x', level: 'info', text: 'Address families used: IPv4 and IPv6' },
      ],
    }
    expect(observedExitIPs(r)).toEqual(['203.0.113.9', '2001:db8:85a3::8a2e:370:7334'])
  })
})

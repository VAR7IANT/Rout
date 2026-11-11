// Page-level tests: each one drives a page through the interface and checks what is sent to
// the server, since a wrong request body is the failure that matters most here.
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import type { AIView, DiagResult, ExitView, NodeList, NodeView, PanelHTTPSReport, SourceView, SubscriptionView, SystemView } from '../core/types'
import { AIPage, isHostPort, observedExitIPs } from '../pages/ai'
import { needsConfirm } from '../pages/node-egress'
import { NodesPage } from '../pages/nodes'
import { forgetPanelReport, loadPanelReport, panelHealth } from '../pages/panel-https'
import { SourcesTab } from '../pages/sources'
import { reorder, SubscriptionEditor } from '../pages/subscription-editor'
import { SystemPage } from '../pages/system'
import { mount, sent, serve } from './harness'

const node = (over: Partial<NodeView> = {}): NodeView => ({
  id: 'n1',
  name: 'Tokyo-VLESS',
  kind: 'node',
  protocol: 'vless',
  label: 'VLESS Reality',
  enabled: true,
  state: 'running',
  listen: '0.0.0.0',
  port: 443,
  public_host: '203.0.113.9',
  public_port: 443,
  networks: ['tcp'],
  subscriptions: ['Family'],
  warnings: [],
  has_link: true,
  ...over,
})

const nodeList = (nodes: NodeView[]): NodeList => ({
  nodes,
  protocols: [
    { id: 'vless', label: 'VLESS Reality', networks: ['tcp'] },
    { id: 'hy2', label: 'Hysteria2', networks: ['udp'] },
  ],
  exits: [{ id: 'x1', name: 'US-SOCKS', kind: 'classic' }],
  host: { ipv4: true, ipv6: false },
  monitoring: false,
  outbound_policies: [
    { policy: 'auto', available: true },
    { policy: 'ipv6_only', available: false, missing: 'IPv6' },
  ],
})

describe('nodes', () => {
  it('lists nodes and filters them by text and state', async () => {
    serve({ 'GET /api/nodes': () => ({ body: nodeList([node(), node({ id: 'n2', name: 'Osaka-HY2', protocol: 'hy2', label: 'Hysteria2', state: 'stopped', warnings: ['cert_expired'] })]) }) })
    mount(<NodesPage />)
    expect(await screen.findByText('Tokyo-VLESS')).toBeInTheDocument()
    expect(screen.getByText('Certificate expired')).toBeInTheDocument()
    await userEvent.type(screen.getByRole('searchbox'), 'osaka')
    await waitFor(() => expect(screen.queryByText('Tokyo-VLESS')).not.toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /clear filters/i }))
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'State' }), 'running')
    expect(await screen.findByText('Tokyo-VLESS')).toBeInTheDocument() // the text filter is debounced
    expect(screen.queryByText('Osaka-HY2')).not.toBeInTheDocument()
  })

  it('creates nodes with exactly the chosen options', async () => {
    const calls = serve({ 'GET /api/nodes': () => ({ body: nodeList([]) }), 'POST /api/nodes': () => ({ body: { nodes: [node()] } }) })
    mount(<NodesPage />)
    await userEvent.click((await screen.findAllByRole('button', { name: /new nodes/i }))[0])
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText(/name prefix/i), ' Tokyo ')
    await userEvent.type(within(dialog).getByLabelText(/^port/i), '8443')
    await userEvent.type(within(dialog).getByLabelText(/camouflage/i), 'www.example.com')
    await userEvent.selectOptions(within(dialog).getByLabelText(/^exit/i), 'x1')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(sent(calls, 'POST', '/api/nodes')).toHaveLength(1))
    expect(sent(calls, 'POST', '/api/nodes')[0].body).toEqual({ base_name: 'Tokyo', protocols: ['vless'], inbound: '', reality_sni: 'www.example.com', exit_id: 'x1', port: 8443, outbound_policy: '', force: false })
  })

  it('drops the fixed port when several nodes are created, and the Reality SNI when no protocol uses it', async () => {
    const calls = serve({ 'GET /api/nodes': () => ({ body: nodeList([]) }), 'POST /api/nodes': () => ({ body: { nodes: [] } }) })
    mount(<NodesPage />)
    await userEvent.click((await screen.findAllByRole('button', { name: /new nodes/i }))[0])
    const dialog = screen.getByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText(/^port/i), '8443')
    await userEvent.type(within(dialog).getByLabelText(/camouflage/i), 'www.example.com')
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /hysteria2/i }))
    expect(within(dialog).queryByLabelText(/^port/i)).not.toBeInTheDocument() // two nodes cannot share one port
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(sent(calls, 'POST', '/api/nodes')).toHaveLength(1))
    expect(sent(calls, 'POST', '/api/nodes')[0].body).toMatchObject({ protocols: ['vless', 'hy2'], port: 0, reality_sni: 'www.example.com' })

    await userEvent.click((await screen.findAllByRole('button', { name: /new nodes/i }))[0])
    const again = screen.getByRole('dialog')
    await userEvent.type(within(again).getByLabelText(/camouflage/i), 'www.example.com')
    await userEvent.click(within(again).getByRole('checkbox', { name: /hysteria2/i }))
    await userEvent.click(within(again).getByRole('checkbox', { name: /vless/i }))
    expect(within(again).queryByLabelText(/camouflage/i)).not.toBeInTheDocument()
    await userEvent.click(within(again).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(sent(calls, 'POST', '/api/nodes')).toHaveLength(2))
    expect(sent(calls, 'POST', '/api/nodes')[1].body).toMatchObject({ protocols: ['hy2'], reality_sni: '' })
  })

  it('refuses to create with no protocol, and an unusable policy needs an explicit tick', async () => {
    serve({ 'GET /api/nodes': () => ({ body: nodeList([]) }) })
    mount(<NodesPage />)
    await userEvent.click((await screen.findAllByRole('button', { name: /new nodes/i }))[0])
    const dialog = screen.getByRole('dialog')
    const create = within(dialog).getByRole('button', { name: 'Create' })
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /vless/i }))
    expect(create).toBeDisabled()
    expect(within(dialog).getByRole('alert')).toHaveTextContent(/at least one protocol/i)
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /vless/i }))
    await userEvent.selectOptions(within(dialog).getByLabelText(/outbound ip family/i), 'ipv6_only')
    expect(create).toBeDisabled()
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /no IPv6 route/i }))
    expect(create).toBeEnabled()
  })

  it('deletes after the consequences are shown, asking for the password when the server demands it', async () => {
    let verified = false
    let deleted = false
    const calls = serve({
      'GET /api/nodes': () => ({ body: nodeList(deleted ? [] : [node()]) }),
      'POST /api/reauth': () => {
        verified = true
        return {}
      },
      'DELETE /api/nodes/n1': () => {
        if (!verified) return { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } }
        deleted = true
        return {}
      },
    })
    mount(<NodesPage />)
    await userEvent.click(await screen.findByRole('button', { name: /more actions/i }))
    await userEvent.click(screen.getByRole('menuitem', { name: 'Delete' }))
    expect(screen.getByText(/removed from these subscriptions: Family/i)).toBeInTheDocument()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw{Enter}')
    await waitFor(() => expect(screen.queryByText('Tokyo-VLESS')).not.toBeInTheDocument())
    expect(sent(calls, 'DELETE', '/api/nodes/n1')).toHaveLength(2)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('applies bulk actions to the selected rows', async () => {
    const calls = serve({ 'GET /api/nodes': () => ({ body: nodeList([node(), node({ id: 'n2', name: 'Osaka' })]) }), 'POST /api/nodes/bulk': () => ({ body: { count: 2 } }) })
    mount(<NodesPage />)
    await userEvent.click(await screen.findByRole('checkbox', { name: /select all/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(sent(calls, 'POST', '/api/nodes/bulk')).toHaveLength(1))
    expect(sent(calls, 'POST', '/api/nodes/bulk')[0].body).toEqual({ action: 'disable', ids: ['n1', 'n2'] })
  })

  it('needsConfirm only for an unavailable, unacknowledged choice', () => {
    const choices = nodeList([]).outbound_policies
    expect(needsConfirm(choices, 'auto', false)).toBe(false)
    expect(needsConfirm(choices, 'ipv6_only', false)).toBe(true)
    expect(needsConfirm(choices, 'ipv6_only', true)).toBe(false)
    expect(needsConfirm(undefined, 'ipv6_only', false)).toBe(false)
  })
})

const exit = (over: Partial<ExitView> = {}): ExitView => ({ id: 'x1', name: 'US-SOCKS', kind: 'classic', protocol: 'socks5', label: 'SOCKS5', host: '198.51.100.4', port: 1080, has_auth: true, transport: 'tcp', nodes: [], node_ids: [], ai: false, refs: 0, ai_usable: true, path: ['This server', 'SOCKS5 198.51.100.4:1080', 'Internet'], ...over })
const aiView = (over: Partial<AIView> = {}): AIView => ({
  enabled: false,
  rule_set: 3,
  rule_set_available: 3,
  problems: [],
  nodes: [
    { id: 'n1', name: 'Tokyo', protocol: 'VLESS', bound: true, eligible: true, running: 'Running', in_sync: true, exit: 'direct' },
    { id: 'n2', name: 'Osaka', protocol: 'HY2', bound: false, eligible: true, running: 'Running', in_sync: true, exit: 'direct' },
    { id: 'n3', name: 'Relay-only', protocol: 'SS', bound: false, eligible: false, running: 'Stopped', in_sync: true, exit: 'direct', note: 'has no inbound' },
  ],
  exits: [exit(), exit({ id: 'x2', name: 'Broken', ai_usable: false, ai_problem: 'UDP only' })],
  relays: [],
  services: [{ name: 'OpenAI', suffixes: ['openai.com'] }],
  limits: ['Only domains are matched'],
  ...over,
})

describe('AI routing', () => {
  it('saves the ticked inbound nodes in the server order and shows the answer', async () => {
    const calls = serve({ 'GET /api/ai': () => ({ body: aiView() }), 'PUT /api/ai/bindings': () => ({ body: aiView({ nodes: aiView().nodes.map((n) => ({ ...n, bound: n.id !== 'n3' })) }) }) })
    mount(<AIPage />)
    const save = await screen.findByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: /relay-only/i })).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: /osaka/i }))
    await userEvent.click(save)
    await waitFor(() => expect(sent(calls, 'PUT', '/api/ai/bindings')).toHaveLength(1))
    expect(sent(calls, 'PUT', '/api/ai/bindings')[0].body).toEqual({ ids: ['n1', 'n2'] })
    await waitFor(() => expect(save).toBeDisabled()) // the checklist now equals what the server has
  })

  it('switches routing on with one call and offers only usable exits', async () => {
    const calls = serve({ 'GET /api/ai': () => ({ body: aiView() }), 'POST /api/ai/enabled': () => ({ body: aiView({ enabled: true }) }), 'PUT /api/ai/exit': () => ({ body: aiView({ exit_id: 'x1', exit: exit() }) }) })
    mount(<AIPage />)
    await userEvent.click(await screen.findByRole('switch'))
    await waitFor(() => expect(sent(calls, 'POST', '/api/ai/enabled')[0]?.body).toEqual({ enabled: true }))
    expect(screen.getByRole('radio', { name: /broken/i })).toBeDisabled()
    expect(screen.getByText('UDP only')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('radio', { name: /us-socks/i }))
    await userEvent.click(screen.getByRole('button', { name: /use.*exit/i }))
    await waitFor(() => expect(sent(calls, 'PUT', '/api/ai/exit')[0]?.body).toEqual({ exit_id: 'x1' }))
  })

  it('reads the observed exit addresses from the exit layer only', () => {
    const result: DiagResult = {
      ok: true,
      steps: [
        { layer: 2, layer_name: 'Relay', level: 'ok', text: 'relay 10.0.0.5:2000 reachable' },
        { layer: 6, layer_name: 'Exit', level: 'ok', text: 'Exit IP 203.0.113.7' },
        { layer: 6, layer_name: 'Exit', level: 'fail', text: 'IPv6 exit 2001:db8::9 refused' },
        { layer: 6, layer_name: 'Exit', level: 'ok', text: 'again 203.0.113.7' },
      ],
    }
    expect(observedExitIPs(result)).toEqual(['203.0.113.7'])
  })

  it('accepts only host:port forwarders', () => {
    for (const good of ['203.0.113.7:20001', 'relay.example.com:443', '[2001:db8::1]:8443', ' 10.0.0.1:1 ']) expect(isHostPort(good)).toBe(true)
    for (const bad of ['203.0.113.7', 'host:0', 'host:70000', '2001:db8::1:443', 'a b:80', ':80']) expect(isHostPort(bad)).toBe(false)
  })
})

describe('subscription editor', () => {
  const choices = [
    { id: 'n1', name: 'Tokyo', protocol: 'vless', label: 'VLESS', kind: 'node' as const, enabled: true },
    { id: 'n2', name: 'Osaka', protocol: 'hy2', label: 'HY2', kind: 'node' as const, enabled: true },
    { id: 'n3', name: 'Stopped', protocol: 'ss', label: 'SS', kind: 'node' as const, enabled: false },
  ]

  it('reorder moves one item and ignores impossible moves', () => {
    expect(reorder(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a'])
    expect(reorder(['a', 'b', 'c'], 2, 0)).toEqual(['c', 'a', 'b'])
    const same = ['a', 'b']
    expect(reorder(same, 0, 0)).toBe(same)
    expect(reorder(same, 0, 5)).toBe(same)
    expect(reorder(same, -1, 0)).toBe(same)
  })

  it('creates a standard subscription as an ordered list of node ids', async () => {
    const calls = serve({ 'POST /api/subscriptions': () => ({ body: {} }) })
    let saved: boolean | null = null
    mount(<SubscriptionEditor choices={choices} onClose={() => undefined} onSaved={async (created) => void (saved = created)} />)
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(screen.getByRole('alert')).toBeInTheDocument() // a name is required
    await userEvent.type(screen.getByLabelText(/name/i, { selector: 'input[maxlength="40"]' }), 'Family')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(sent(calls, 'POST', '/api/subscriptions')).toHaveLength(0) // and at least one node

    expect(screen.getByRole('button', { name: /add: stopped/i })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: /add: tokyo/i }))
    await userEvent.click(screen.getByRole('button', { name: /add: osaka/i }))
    await userEvent.click(screen.getAllByRole('button', { name: /move up/i })[1]) // Osaka first
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(saved).toBe(true))
    expect(sent(calls, 'POST', '/api/subscriptions')[0].body).toEqual({ name: 'Family', node_ids: ['n2', 'n1'] })
  })

  it('saves an aggregate with per-subscription names and never sends allow_insecure without remote nodes', async () => {
    const sub: SubscriptionView = {
      id: 's1',
      name: 'Mix',
      enabled: true,
      aggregate: true,
      dedupe: true,
      allow_insecure: true,
      created_at: '',
      local_count: 1,
      remote_count: 0,
      can_reveal_url: true,
      items: [{ kind: 'local', node_id: 'n1', name: 'Tokyo', protocol: 'vless', status: 'ok', base64_ok: true, mihomo_ok: true }],
    }
    const calls = serve({ 'GET /api/sources': () => ({ body: { sources: [] } }), 'PUT /api/subscriptions/s1/items': () => ({ body: {} }) })
    mount(<SubscriptionEditor sub={sub} choices={choices} onClose={() => undefined} onSaved={async () => undefined} />)
    expect(screen.getByRole('radio', { name: /standard/i })).toBeDisabled() // an aggregate cannot be downgraded
    await userEvent.type(screen.getByRole('textbox', { name: /tokyo/i }), 'JP 01')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(sent(calls, 'PUT', '/api/subscriptions/s1/items')).toHaveLength(1))
    expect(sent(calls, 'PUT', '/api/subscriptions/s1/items')[0].body).toEqual({ items: [{ kind: 'local', node_id: 'n1', name: 'JP 01' }], aggregate: true, dedupe: true, allow_insecure: false })
  })
})

describe('sources', () => {
  const source: SourceView = { id: 'src1', name: 'Provider', tags: [], kind: 'url', enabled: true, interval_min: 360, created_at: '', status: { state: 'ok' }, entries: 3, valid: 3, active: 3, errors: 0, skipped: 0, duplicates: 0, disabled: 0, refs: ['Mix'] }

  it('will not delete a source in use until detaching is ticked, then says so to the server', async () => {
    const calls = serve({ 'GET /api/sources': () => ({ body: { sources: [source] } }), 'DELETE /api/sources/src1': () => ({}) })
    mount(<SourcesTab />)
    await userEvent.click(await screen.findByRole('button', { name: /more actions/i }))
    await userEvent.click(screen.getByRole('menuitem', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog')
    const del = within(dialog).getByRole('button', { name: 'Delete' })
    expect(del).toBeDisabled()
    await userEvent.click(within(dialog).getByRole('checkbox'))
    await userEvent.click(del)
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE' && c.path === '/api/sources/src1?detach=1')).toBe(true))
  })

  it('rejects a refresh interval under 15 minutes but allows 0 (manual only)', async () => {
    const calls = serve({ 'GET /api/sources': () => ({ body: { sources: [] } }), 'POST /api/sources': () => ({ body: { source: { ...source, kind: 'static', refs: [] } } }), 'GET /api/sources/src1/nodes': () => ({ body: { nodes: [], issues: [] } }) })
    mount(<SourcesTab />)
    await userEvent.click((await screen.findAllByRole('button', { name: /add source|new source|source/i }))[0])
    const dialog = screen.getByRole('dialog')
    const interval = within(dialog).getByLabelText(/interval/i)
    const submit = within(dialog).getAllByRole('button').at(-1)!
    await userEvent.clear(interval)
    await userEvent.type(interval, '5')
    expect(submit).toBeDisabled()
    await userEvent.clear(interval)
    await userEvent.type(interval, '0')
    expect(submit).toBeEnabled()
    await userEvent.type(within(dialog).getByRole('textbox', { name: /url/i }), 'https://example.com/sub')
    await userEvent.click(submit)
    await waitFor(() => expect(sent(calls, 'POST', '/api/sources')).toHaveLength(1))
    expect(sent(calls, 'POST', '/api/sources')[0].body).toMatchObject({ url: 'https://example.com/sub', content: '', interval_min: 0, enabled: true, tags: [] })
  })
})

const report = (over: Partial<PanelHTTPSReport> = {}): PanelHTTPSReport => ({
  domain: 'panel.example.com',
  ownership: 'managed',
  pending: false,
  network: { ipv4: '203.0.113.9', ipv4_nat: false, ipv6_nat: false, ipv6_only: false },
  verification: { local_service: true, host_allowed: true, local_tls: true, public_https: true, login_page: true, certificate_error: false },
  checks: [],
  ...over,
})

describe('panel HTTPS', () => {
  beforeEach(forgetPanelReport)

  it('sums a report up in one word, worst first', () => {
    expect(panelHealth(report({ domain: '' })).key).toBe('panel.health.none')
    expect(panelHealth(report()).key).toBe('panel.health.ok')
    expect(panelHealth(report({ pending: true })).key).toBe('panel.health.pending')
    expect(panelHealth(report({ verification: { ...report().verification, login_page: false } })).key).toBe('panel.health.pending')
    expect(panelHealth(report({ pending: true, checks: [{ key: 'dns', level: 'fail', text: 'x' }] })).key).toBe('panel.health.fail')
    expect(panelHealth(report({ verification: { ...report().verification, certificate_error: true } })).tone).toBe('error')
  })

  it('shares one slow diagnosis between callers until a fresh one is asked for', async () => {
    const calls = serve({ 'GET /api/system/panel': () => ({ body: report() }) })
    const [a, b] = await Promise.all([loadPanelReport(), loadPanelReport()])
    expect(a).toEqual(b)
    await loadPanelReport()
    expect(calls).toHaveLength(1)
    await loadPanelReport(true)
    expect(calls).toHaveLength(2)
  })

  it('does not cache a failure', async () => {
    let fail = true
    serve({ 'GET /api/system/panel': () => (fail ? { status: 500 } : { body: report() }) })
    await expect(loadPanelReport()).rejects.toMatchObject({ status: 500 })
    fail = false
    await expect(loadPanelReport()).resolves.toMatchObject({ domain: 'panel.example.com' })
  })
})

describe('system', () => {
  const system: SystemView = {
    version: '0.6.1',
    update: { current: '0.6.1', available: false },
    runtime: { os: 'Debian 12', arch: 'amd64', go: 'go1.25', init: 'systemd' },
    system: { cpu_percent: 1, cores: 1, load1: 0, mem_total: 1, mem_used: 1, swap_total: 0, swap_used: 0, disk_total: 1, disk_used: 1, net_rx_rate: 0, net_tx_rate: 0, net_rx_total: 0, net_tx_total: 0, uptime_sec: 60, history: null },
    services: [],
    web: { port: 8790, allowed_hosts: ['panel.example.com'], session_idle_min: 60, session_max_hours: 12, secure_cookie: false, password_set: true, secure_request: false },
    subscription: { enabled: false, running: false, managed: false, port: 8787 },
    permissions: [],
  }
  const routes = { 'GET /api/system': () => ({ body: system }), 'GET /api/sessions': () => ({ body: { sessions: [] } }), 'GET /api/activity': () => ({ body: { entries: [] } }) }

  it('opens the tab named in the address', async () => {
    window.history.replaceState(null, '', '/system?tab=security')
    serve(routes)
    mount(<SystemPage />)
    expect(await screen.findByRole('tab', { name: /security/i })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByLabelText(/idle/i)).toHaveValue('60')
    window.history.replaceState(null, '', '/')
  })

  it('validates panel settings and warns before a change that would lock this browser out', async () => {
    window.history.replaceState(null, '', '/system?tab=security')
    const calls = serve({ ...routes, 'PATCH /api/system/settings': () => ({ body: { restart_required: true } }) })
    mount(<SystemPage />)
    const port = await screen.findByLabelText(/port/i)
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled() // nothing changed yet
    await userEvent.clear(port)
    await userEvent.type(port, '80')
    expect(save).toBeDisabled() // below 1024
    await userEvent.clear(port)
    await userEvent.type(port, '9000')
    await userEvent.type(screen.getByLabelText(/host/i), '\nadmin.example.com')
    await userEvent.click(screen.getByRole('checkbox', { name: /secure/i }))
    await userEvent.click(save)
    // Plain HTTP + Secure cookies: an extra confirmation instead of a direct save.
    expect(sent(calls, 'PATCH', '/api/system/settings')).toHaveLength(0)
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(sent(calls, 'PATCH', '/api/system/settings')).toHaveLength(1))
    expect(sent(calls, 'PATCH', '/api/system/settings')[0].body).toEqual({ port: 9000, session_idle_min: 60, session_max_hours: 12, secure_cookie: true, allowed_hosts: ['panel.example.com', 'admin.example.com'] })
    window.history.replaceState(null, '', '/')
  })
})

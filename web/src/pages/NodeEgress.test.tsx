import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { EgressReport, NodeView, PolicyChoice } from '../lib/types'
import { mockFetch, renderApp } from '../test-utils'
import { EgressReportView, EgressSection, PolicyPicker, policyNeedsConfirm } from './NodeEgress'

afterEach(() => vi.unstubAllGlobals())

const dual: PolicyChoice[] = (['auto', 'ipv4_first', 'ipv6_first', 'ipv4_only', 'ipv6_only'] as const).map((policy) => ({ policy, available: true }))
const v4Only: PolicyChoice[] = dual.map((c) => (c.policy === 'ipv6_first' ? { ...c, missing: 'IPv6' as const } : c.policy === 'ipv6_only' ? { ...c, available: false, missing: 'IPv6' as const } : c))

const node = (over: Partial<NodeView> = {}): NodeView => ({
  id: 'abc123abc123',
  name: 'Turkey-VLESS',
  kind: 'node',
  protocol: 'vless',
  label: 'VLESS',
  enabled: true,
  state: 'running',
  listen: '0.0.0.0',
  port: 443,
  public_host: '203.0.113.10',
  public_port: 443,
  networks: ['tcp'],
  subscriptions: [],
  warnings: [],
  has_link: true,
  outbound_policy: 'auto',
  outbound_scope: 'direct',
  outbound_enforced: false,
  ...over,
})

function Harness({ choices }: { choices: PolicyChoice[] }) {
  const [v, setV] = useState('auto')
  const [ok, setOk] = useState(false)
  return (
    <>
      <PolicyPicker value={v} onChange={setV} choices={choices} confirmed={ok} onConfirm={setOk} />
      <output data-testid="state">{`${v}|${ok}|${policyNeedsConfirm(choices, v, ok)}`}</output>
    </>
  )
}

describe('PolicyPicker', () => {
  it('offers the five policies in the fixed order and explains the choice', async () => {
    renderApp(<Harness choices={dual} />)
    const opts = within(screen.getByRole('combobox')).getAllByRole('option').map((o) => o.textContent)
    expect(opts).toEqual(['Auto', 'IPv4 first', 'IPv6 first', 'IPv4 only', 'IPv6 only'])
    expect(screen.getByText(/behaves exactly like|Same as earlier versions/)).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv6_first')
    expect(screen.getByText(/This is not the same as IPv6 only/)).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv6_only')
    expect(screen.getByText(/no IPv4 fallback/)).toBeInTheDocument()
  })

  it('on a host without IPv6 marks the family and requires a deliberate confirmation for IPv6 only', async () => {
    renderApp(<Harness choices={v4Only} />)
    expect(screen.getByRole('option', { name: /IPv6 first — This server has no IPv6 route/ })).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv6_only')
    expect(screen.getByTestId('state')).toHaveTextContent('ipv6_only|false|true')
    await userEvent.click(screen.getByRole('checkbox'))
    expect(screen.getByTestId('state')).toHaveTextContent('ipv6_only|true|false')
    // choosing something else clears the confirmation
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv4_only')
    expect(screen.getByTestId('state')).toHaveTextContent('ipv4_only|false|false')
    // IPv6 first is not blocked: it simply behaves like IPv4
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv6_first')
    expect(screen.getByTestId('state')).toHaveTextContent('ipv6_first|false|false')
  })
})

describe('EgressSection', () => {
  it('saves the policy through the API, with force only after confirmation', async () => {
    const calls: unknown[] = []
    const m = mockFetch({
      'PUT /api/nodes/abc123abc123/outbound-policy': (c) => {
        calls.push(c.body)
        return { body: { nodes: [] } }
      },
    })
    vi.stubGlobal('fetch', m.impl)
    const changed = vi.fn(async () => undefined)
    renderApp(<EgressSection node={node()} choices={v4Only} onChanged={changed} />)
    const save = screen.getByRole('button', { name: 'Save policy' })
    expect(save).toBeDisabled() // nothing changed yet
    await userEvent.selectOptions(screen.getByRole('combobox'), 'ipv6_only')
    expect(save).toBeDisabled() // unusable choice needs the confirmation first
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(save)
    await waitFor(() => expect(changed).toHaveBeenCalled())
    expect(calls).toEqual([{ policy: 'ipv6_only', force: true }])
  })

  it('shows the effective policy, whether it is enforced, and the scope note for a proxy exit', () => {
    renderApp(<EgressSection node={node({ outbound_policy: 'ipv6_only', outbound_scope: 'proxy', outbound_enforced: false, outbound_note: 'Only the connection to the proxy server is limited.' })} choices={dual} onChanged={async () => undefined} />)
    expect(screen.getByText('Not enforced')).toBeInTheDocument()
    expect(screen.getByText('Only the connection to the proxy server is limited.')).toBeInTheDocument()
  })

  it('runs the egress test through the node and labels host and node measurements separately', async () => {
    const report: EgressReport = {
      policy: 'ipv6_only',
      policy_label: 'IPv6 only',
      scope: 'direct',
      enforced: true,
      quick: false,
      host: { v4: { route: true, dns: true, ip: '203.0.113.10' }, v6: { route: true, dns: true, ip: '2001:db8::10' } },
      node: { v4: { error: 'refused', literal_tried: true, literal_ok: false }, v6: { ip: '2001:db8::10', literal_tried: true, literal_ok: true } },
      checks: [
        { key: 'allowed', status: 'pass', text: 'IPv6 connection succeeded' },
        { key: 'denied_name', status: 'pass', text: 'IPv4 fallback blocked' },
      ],
      result: 'pass',
    }
    const m = mockFetch({ 'POST /api/nodes/abc123abc123/egress-test': () => ({ body: report }) })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<EgressSection node={node({ outbound_policy: 'ipv6_only', outbound_enforced: true })} choices={dual} onChanged={async () => undefined} />)
    await userEvent.click(screen.getByRole('button', { name: 'Test outbound network' }))
    expect(await screen.findByText('Result: passed')).toBeInTheDocument()
    expect(screen.getByText('Host network test (this server itself, not through the node)')).toBeInTheDocument()
    expect(screen.getByText('Node egress test (through the node’s real exit)')).toBeInTheDocument()
    expect(m.calls.find((c) => c.path.endsWith('/egress-test'))?.body).toEqual({ quick: false })
  })
})

describe('EgressReportView', () => {
  const base: EgressReport = {
    policy: 'ipv6_only',
    policy_label: 'IPv6 only',
    scope: 'direct',
    enforced: true,
    quick: false,
    host: { v4: { route: true, dns: true }, v6: { route: false, dns: false } },
    node: { v4: { literal_tried: false, literal_ok: false }, v6: { literal_tried: false, literal_ok: false } },
    checks: [],
    result: 'inconclusive',
  }
  it('never presents an unverifiable result as a pass', () => {
    renderApp(<EgressReportView report={{ ...base, checks: [{ key: 'denied_name', status: 'inconclusive', text: 'Cannot prove IPv4 is blocked' }] }} />)
    expect(screen.getByText(/could not be fully verified/)).toBeInTheDocument()
    expect(screen.queryByText('Result: passed')).toBeNull()
  })
  it('reports a failure plainly', () => {
    renderApp(<EgressReportView report={{ ...base, result: 'fail', checks: [{ key: 'denied_name', status: 'fail', text: 'The policy is not in effect' }] }} />)
    expect(screen.getByText('Result: failed')).toBeInTheDocument()
  })
  it('a quick look that could not finish says so instead of showing the quick message', () => {
    renderApp(<EgressReportView report={{ ...base, quick: true, result: 'inconclusive', checks: [{ key: 'aborted', status: 'inconclusive', text: 'The test client stopped early' }] }} />)
    expect(screen.getByText(/could not be fully verified/)).toBeInTheDocument()
    expect(screen.queryByText(/Showing the addresses seen through the node/)).toBeNull()
  })
  it('the quick view only lists addresses', () => {
    renderApp(<EgressReportView report={{ ...base, quick: true, result: '', checks: [{ key: 'node_v6', status: 'info', text: 'IPv6 exit 2001:db8::1' }] }} />)
    expect(screen.getByText(/Showing the addresses seen through the node/)).toBeInTheDocument()
  })
})

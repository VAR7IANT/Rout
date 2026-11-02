import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SubNodeChoice } from '../lib/types'
import { mockFetch, renderApp } from '../test-utils'
import { SubscriptionEditor } from './SubscriptionEditor'

afterEach(() => vi.unstubAllGlobals())

const choices: SubNodeChoice[] = [
  { id: 'n1', name: 'alpha', protocol: 'vless', label: 'VLESS', kind: 'node', enabled: true },
  { id: 'n2', name: 'bravo', protocol: 'ss', label: 'SS', kind: 'node', enabled: true },
  { id: 'n3', name: 'stopped-one', protocol: 'tuic', label: 'TUIC', kind: 'node', enabled: false },
]

const source = { id: 's1', name: 'Airport', tags: [], kind: 'url', enabled: true, interval_min: 60, created_at: '', status: { state: 'ok' }, entries: 2, valid: 2, active: 2, errors: 0, skipped: 0, duplicates: 0, disabled: 0, refs: [] }
const remoteNodes = [
  { id: 'r1', name: 'HK 01', protocol: 'hysteria2', server: 'h.example', port: 443, udp: true, enabled: true, link_ok: true, from_clash: false },
  { id: 'r2', name: 'JP off', protocol: 'trojan', server: 'j.example', port: 443, udp: false, enabled: false, link_ok: true, from_clash: false },
]

function setup(extra: Parameters<typeof mockFetch>[0] = {}) {
  const m = mockFetch({
    'GET /api/sources': () => ({ body: { sources: [source] } }),
    'GET /api/sources/s1/nodes': () => ({ body: { nodes: remoteNodes, issues: [] } }),
    ...extra,
  })
  vi.stubGlobal('fetch', m.impl)
  const onSaved = vi.fn(async () => undefined)
  renderApp(<SubscriptionEditor choices={choices} onClose={() => undefined} onSaved={onSaved} />)
  return { m, onSaved }
}

describe('SubscriptionEditor', () => {
  it('creates a standard subscription from local nodes, in the order chosen', async () => {
    const { m, onSaved } = setup({ 'POST /api/subscriptions': () => ({ body: { id: 'x' } }) })
    await userEvent.type(screen.getByLabelText(/name/i, { selector: 'input' }), 'daily')
    const pool = screen.getByRole('region', { name: /available/i })
    await userEvent.click(within(pool).getAllByRole('button', { name: 'Add' })[1]!) // bravo first
    await userEvent.click(within(pool).getAllByRole('button', { name: 'Add' })[0]!)
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    const post = m.calls.find((c) => c.method === 'POST')!
    expect(post.body).toEqual({ name: 'daily', node_ids: ['n2', 'n1'] })
    // third-party nodes are not even requested for a standard subscription
    expect(m.calls.some((c) => c.path === '/api/sources')).toBe(false)
  })

  it('does not let a stopped node be added', async () => {
    setup()
    const pool = screen.getByRole('region', { name: /available/i })
    const row = within(pool).getByText('stopped-one').closest('li')!
    expect(within(row).getByRole('button', { name: 'Add' })).toBeDisabled()
  })

  it('refuses to save an empty selection', async () => {
    const { m } = setup()
    await userEvent.type(screen.getByLabelText(/name/i, { selector: 'input' }), 'empty')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(m.calls.some((c) => c.method === 'POST')).toBe(false)
  })

  it('mixes in third-party nodes as an aggregate and sends their identity and custom names', async () => {
    const { m, onSaved } = setup({ 'POST /api/subscriptions': () => ({ body: { id: 'x' } }) })
    await userEvent.type(screen.getByLabelText(/name/i, { selector: 'input' }), 'mix')
    await userEvent.click(screen.getByRole('radio', { name: /aggregate/i }))
    const pool = screen.getByRole('region', { name: /available/i })
    await within(pool).findByText('HK 01')
    // a node that the source switched off is not offered
    expect(within(pool).queryByText('JP off')).toBeNull()
    await userEvent.click(within(pool).getAllByRole('button', { name: 'Add' })[0]!) // alpha
    const hk = within(pool).getByText('HK 01').closest('li')!
    await userEvent.click(within(hk).getByRole('button', { name: 'Add' }))
    const selected = screen.getByRole('region', { name: /in this subscription/i })
    await userEvent.type(within(selected).getAllByRole('textbox')[1]!, '🇭🇰 Hong Kong')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    const post = m.calls.find((c) => c.method === 'POST')!
    expect(post.body).toMatchObject({
      name: 'mix',
      aggregate: true,
      items: [
        { kind: 'local', node_id: 'n1' },
        { kind: 'remote', source_id: 's1', remote_id: 'r1', name: '🇭🇰 Hong Kong' },
      ],
    })
    // certificate verification stays on unless the administrator opts out
    expect((post.body as { allow_insecure: boolean }).allow_insecure).toBe(false)
  })

  it('moves entries up and down', async () => {
    setup({ 'POST /api/subscriptions': () => ({ body: { id: 'x' } }) })
    const pool = screen.getByRole('region', { name: /available/i })
    await userEvent.click(screen.getByRole('button', { name: /add all shown/i }))
    const selected = screen.getByRole('region', { name: /in this subscription/i })
    const names = () => within(selected).getAllByRole('listitem').map((li) => li.querySelector('strong')?.textContent)
    expect(names()).toEqual(['alpha', 'bravo'])
    await userEvent.click(within(selected).getAllByRole('button', { name: 'Move down' })[0]!)
    expect(names()).toEqual(['bravo', 'alpha'])
    expect(pool).toBeInTheDocument()
  })
})

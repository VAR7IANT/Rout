import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { PanelHTTPSReport } from '../lib/types'
import { mockFetch, renderApp } from '../test-utils'
import { PanelHTTPSCard, panelHealth, resetPanelCache } from './PanelHTTPS'

beforeEach(() => resetPanelCache())
afterEach(() => vi.unstubAllGlobals())

const report: PanelHTTPSReport = {
  domain: 'panel.very-long-subdomain-for-testing.example.com',
  ownership: 'managed',
  pending: true,
  last_error: 'ACME challenge timed out',
  network: { ipv6: '2001:db8:85a3:0000:0000:8a2e:0370:7334', ipv4_nat: false, ipv6_nat: false, ipv6_only: true },
  records: ['AAAA panel.very-long-subdomain-for-testing.example.com → 2001:db8:85a3::8a2e:370:7334'],
  verification: { local_service: true, host_allowed: true, local_tls: false, public_https: false, login_page: false, certificate_error: false, expires: '0001-01-01T00:00:00Z' },
  checks: [
    { key: 'service', level: 'ok', text: 'Panel answers on 127.0.0.1:8790' },
    { key: 'ports', level: 'fail', text: 'Nothing listens on TCP 443' },
  ],
  url: 'https://panel.very-long-subdomain-for-testing.example.com',
}

describe('PanelHTTPSCard', () => {
  it('shows the domain, network facts, records and checks', async () => {
    const m = mockFetch({ 'GET /api/system/panel': () => ({ body: report }) })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<PanelHTTPSCard />)
    expect(await screen.findByRole('link', { name: report.url })).toHaveAttribute('href', report.url)
    expect(screen.getByText('IPv6-only server')).toBeInTheDocument()
    expect(screen.getByText('Managed by Rout')).toBeInTheDocument()
    expect(screen.getByText('Waiting for issue / verification')).toBeInTheDocument()
    expect(screen.getByText(report.records![0]!)).toBeInTheDocument()
    expect(screen.getByText('Nothing listens on TCP 443')).toBeInTheDocument()
    expect(screen.getByText('ACME challenge timed out')).toBeInTheDocument()
    expect(screen.getByText('HTTPS has problems')).toBeInTheDocument()
    expect(screen.getByText(/sudo rout web setup/)).toBeInTheDocument()
  })

  it('re-checks without the cache and repairs behind the password prompt', async () => {
    let repairs = 0
    const m = mockFetch({
      'GET /api/system/panel': () => ({ body: report }),
      'POST /api/system/panel/repair': () => {
        repairs++
        return repairs === 1 ? { status: 403, body: { error: { code: 'reauth_required', message: 'again' } } } : { body: { ok: false, pending: true, diagnosis: 'Certificate not issued yet' } }
      },
      'POST /api/reauth': () => ({ body: { ok: true } }),
    })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<PanelHTTPSCard />)
    await screen.findByText('Nothing listens on TCP 443')
    await userEvent.click(screen.getByRole('button', { name: 'Re-check' }))
    await waitFor(() => expect(m.calls.filter((c) => c.path === '/api/system/panel').length).toBe(2))

    await userEvent.click(screen.getByRole('button', { name: 'Repair HTTPS' }))
    await userEvent.type(await screen.findByLabelText('Administrator password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: 'Verify and continue' }))
    expect(await screen.findByText('Certificate not issued yet')).toBeInTheDocument()
    expect(repairs).toBe(2)
    expect(m.calls.find((c) => c.path === '/api/reauth')!.body).toEqual({ password: 'pw' })
  })

  it('shows the error when the check fails', async () => {
    const m = mockFetch({ 'GET /api/system/panel': () => ({ status: 409, body: { error: { code: 'conflict', message: 'HTTPS check timed out' } } }) })
    vi.stubGlobal('fetch', m.impl)
    renderApp(<PanelHTTPSCard />)
    expect(await screen.findByText('HTTPS check timed out')).toBeInTheDocument()
  })
})

describe('panelHealth', () => {
  it('summarises a report', () => {
    expect(panelHealth({ ...report, domain: '' }).key).toBe('panel.health.none')
    expect(panelHealth(report).key).toBe('panel.health.fail')
    const good = { ...report, pending: false, checks: [], verification: { ...report.verification, public_https: true, login_page: true, local_tls: true } }
    expect(panelHealth(good).key).toBe('panel.health.ok')
    expect(panelHealth({ ...good, pending: true }).key).toBe('panel.health.pending')
  })
})

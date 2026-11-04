import { useEffect, useState } from 'react'
import { useI18n } from '../i18n'
import { api } from '../lib/api'
import { useResource } from '../lib/hooks'
import { Link } from '../lib/router'
import { formatBytes, formatDate, formatPercent, formatRate, formatUptime } from '../lib/format'
import type { AIView, Alert, Overview, PanelHTTPSReport } from '../lib/types'
import { loadPanelReport, panelHealth } from './PanelHTTPS'
import { LineChart } from '../components/chart'
import { Badge, Button, Card, EmptyState, Meter, Notice, PageHead, Spinner, Stat, type Tone } from '../components/ui'

const linkTargets: Record<string, string> = { nodes: '/nodes', relays: '/relays', subscriptions: '/subscriptions', sources: '/sources', system: '/system' }

export function Dashboard() {
  const { t, tc, locale } = useI18n()
  const { data: o, error, loading, reload } = useResource<Overview>('/api/overview', { interval: 5000 })

  if (loading && !o) return <Spinner label={t('common.loading')} />
  if (!o) {
    return (
      <EmptyState icon="warn" title={t('common.loadFailed')} action={<Button onClick={() => void reload()}>{t('common.retry')}</Button>}>
        {error?.message}
      </EmptyState>
    )
  }

  const sys = o.system
  const hist = sys.history ?? []
  const memPct = formatPercent(sys.mem_used, sys.mem_total)
  const diskPct = formatPercent(sys.disk_used, sys.disk_total)
  const c = o.counts
  const serverText = !o.subscription_server.enabled ? t('dash.serverOff') : !o.subscription_server.managed ? t('dash.serverUnmanaged') : o.subscription_server.running ? t('state.running') : t('state.stopped')
  const serverTone: Tone = !o.subscription_server.enabled || !o.subscription_server.managed ? 'neutral' : o.subscription_server.running ? 'ok' : 'error'

  const alertText = (a: Alert) => tc(`alert.${a.code}`, a.code)

  return (
    <div className="page">
      <PageHead
        title={t('dash.title')}
        subtitle={t('dash.subtitle', { host: sys.hostname ?? 'rout', up: formatUptime(sys.uptime_sec, t) })}
        actions={
          <Button icon="refresh" size="sm" onClick={() => void reload()}>
            {t('common.refresh')}
          </Button>
        }
      />

      {o.update.available ? (
        <Notice tone="accent" title={t('dash.update', { v: o.update.latest ?? '' })}>
          {t('dash.updateHint')}
        </Notice>
      ) : null}

      <Card title={t('dash.alerts')} className="alerts-card">
        {o.alerts.filter((a) => a.code !== 'update_available').length === 0 ? (
          <p className="muted ok-line">
            <Badge tone="ok">OK</Badge> {t('dash.noAlerts')}
          </p>
        ) : (
          <ul className="alert-list">
            {o.alerts
              .filter((a) => a.code !== 'update_available')
              .map((a, i) => (
                <li key={`${a.code}-${a.subject ?? ''}-${i}`}>
                  <Badge tone={a.level === 'error' ? 'error' : a.level === 'warn' ? 'warn' : 'neutral'}>{a.level === 'error' ? '!' : a.level === 'warn' ? '▲' : 'i'}</Badge>
                  <div className="alert-text">
                    <strong>{alertText(a)}</strong>
                    {a.subject ? <span className="mono"> {a.subject}</span> : null}
                    {a.detail ? <div className="muted small">{a.detail}</div> : null}
                  </div>
                  {a.link && linkTargets[a.link] ? (
                    <Link to={linkTargets[a.link]} className="link-quiet">
                      {t('common.details')} →
                    </Link>
                  ) : null}
                </li>
              ))}
          </ul>
        )}
      </Card>

      <div className="stat-grid">
        <Stat label={t('dash.nodes')} value={c.nodes.total} sub={statSub(t, c.nodes)} tone={c.nodes.stopped > 0 ? 'warn' : undefined} />
        <Stat label={t('dash.relays')} value={c.relays.total} sub={statSub(t, c.relays)} tone={c.relays.stopped > 0 ? 'warn' : undefined} />
        <Stat label={t('dash.exits')} value={c.exits} />
        <Stat label={t('dash.subs')} value={c.subscriptions} sub={c.aggregates > 0 ? t('dash.aggregatesN', { n: c.aggregates }) : undefined} />
        <Stat label={t('dash.sources')} value={c.sources} sub={c.sources > 0 ? `${t('dash.sourcesOk', { ok: c.sources_ok, bad: c.sources_failed })} · ${t('dash.remoteNodes', { n: c.remote_nodes })}` : undefined} tone={c.sources_failed > 0 ? 'warn' : undefined} />
        <Stat label={t('dash.subServer')} value={<Badge tone={serverTone}>{serverText}</Badge>} />
      </div>

      <div className="tile-row">
        <AITile />
        <WebTile />
      </div>

      <div className="grid-2">
        <Card title={t('dash.resources')}>
          <div className="resource-grid">
            <div>
              <div className="res-head">
                <span>{t('dash.cpu')}</span>
                <strong>{sys.cpu_percent.toFixed(0)}%</strong>
              </div>
              <Meter percent={sys.cpu_percent} label={t('dash.cpu')} />
              <div className="muted small">
                {t('dash.cores', { n: sys.cores })} · {t('dash.load', { v: sys.load1.toFixed(2) })}
              </div>
            </div>
            <div>
              <div className="res-head">
                <span>{t('dash.memory')}</span>
                <strong>{memPct.toFixed(0)}%</strong>
              </div>
              <Meter percent={memPct} label={t('dash.memory')} />
              <div className="muted small">
                {formatBytes(sys.mem_used)} / {formatBytes(sys.mem_total)}
                {sys.swap_total > 0 ? ` · ${t('dash.swap', { u: formatBytes(sys.swap_used), t: formatBytes(sys.swap_total) })}` : ''}
              </div>
            </div>
            <div>
              <div className="res-head">
                <span>{t('dash.disk')}</span>
                <strong>{diskPct.toFixed(0)}%</strong>
              </div>
              <Meter percent={diskPct} label={t('dash.disk')} />
              <div className="muted small">
                {formatBytes(sys.disk_used)} / {formatBytes(sys.disk_total)}
              </div>
            </div>
          </div>
          <div className="chart-row">
            <div>
              <div className="chart-title">{t('dash.chartCpu')}</div>
              <LineChart label={t('dash.chartCpu')} max={100} series={[{ label: 'cpu', className: 'series-a', values: hist.map((p) => p.cpu) }]} />
            </div>
            <div>
              <div className="chart-title">{t('dash.chartNet')}</div>
              <LineChart
                label={t('dash.chartNet')}
                series={[
                  { label: 'down', className: 'series-a', values: hist.map((p) => p.net_rx_rate) },
                  { label: 'up', className: 'series-b', values: hist.map((p) => p.net_tx_rate) },
                ]}
              />
              <div className="legend">
                <span className="legend-a">▼ {t('dash.down')} {formatRate(sys.net_rx_rate)}</span>
                <span className="legend-b">▲ {t('dash.up')} {formatRate(sys.net_tx_rate)}</span>
              </div>
            </div>
          </div>
        </Card>

        <Card title={t('dash.network')}>
          <div className="net-rows">
            <NetRow family="IPv4" ip={o.network.ipv4} local={o.network.local_ipv4} checking={o.network.checking} />
            <NetRow family="IPv6" ip={o.network.ipv6} local={o.network.local_ipv6} checking={o.network.checking} />
          </div>
        </Card>
      </div>

      <div className="grid-2">
        <Card title={t('dash.traffic')}>
          <div className="traffic-live">
            <Stat label={t('dash.trafficLive')} value={<span className="mono">▼ {formatRate(sys.net_rx_rate)} · ▲ {formatRate(sys.net_tx_rate)}</span>} sub={`${t('dash.since', { d: `▼ ${formatBytes(sys.net_rx_total)} · ▲ ${formatBytes(sys.net_tx_total)}` })}`} />
          </div>
          {o.traffic.monitoring ? (
            <>
              <Stat label={t('dash.trafficTotal')} value={formatBytes(o.traffic.total)} sub={`▼ ${formatBytes(o.traffic.down)} · ▲ ${formatBytes(o.traffic.up)}`} />
              {o.traffic.top.length > 0 ? (
                <div className="top-list">
                  <div className="chart-title">{t('dash.topNodes')}</div>
                  {o.traffic.top.map((n) => (
                    <div key={n.id} className="top-row">
                      <span className="top-name">{n.name}</span>
                      <Meter percent={formatPercent(n.total, o.traffic.top[0]?.total || 1)} tone="accent" label={n.name} />
                      <span className="mono top-val">{formatBytes(n.total)}</span>
                    </div>
                  ))}
                </div>
              ) : null}
            </>
          ) : (
            <Notice tone="neutral" title={t('dash.trafficOff')}>
              {t('dash.trafficOffHint')}
            </Notice>
          )}
        </Card>

        <div className="stack">
          <Card title={t('dash.quotas')}>
            {o.quotas.length === 0 ? (
              <p className="muted">{t('dash.quotasNone')}</p>
            ) : (
              <ul className="quota-list">
                {o.quotas.map((q) => {
                  const pct = formatPercent(q.used, q.limit)
                  return (
                    <li key={`${q.kind}-${q.id}`}>
                      <div className="quota-head">
                        <span>
                          <Badge>{q.kind === 'node' ? t('dash.quotaNode') : t('dash.quotaSub')}</Badge> {q.name}
                        </span>
                        <span className="mono small">
                          {formatBytes(q.used)} / {formatBytes(q.limit)}
                        </span>
                      </div>
                      <Meter percent={pct} label={q.name} />
                      {q.next_reset ? <div className="muted small">{t('common.resets', { d: formatDate(q.next_reset, locale) })}</div> : null}
                    </li>
                  )
                })}
              </ul>
            )}
          </Card>
          <Card title={t('dash.certs')}>
            {o.certs.length === 0 ? (
              <p className="muted">{t('dash.certsNone')}</p>
            ) : (
              <ul className="cert-list">
                {o.certs.map((c2) => (
                  <li key={c2.id}>
                    <span>{c2.name}</span>
                    <span>
                      {c2.self_signed ? <Badge>{t('dash.selfSigned')}</Badge> : null}{' '}
                      <Badge tone={c2.days < 0 ? 'error' : c2.days <= 14 ? 'warn' : 'ok'}>{c2.days < 0 ? t('dash.certExpired', { n: -c2.days }) : t('dash.certDays', { n: c2.days })}</Badge>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}

function statSub(t: ReturnType<typeof useI18n>['t'], s: { total: number; running: number; stopped: number; disabled: number }) {
  if (s.total === 0) return undefined
  const parts = [t('dash.runningOf', { r: s.running, n: s.total })]
  if (s.stopped > 0) parts.push(t('dash.stoppedN', { n: s.stopped }))
  if (s.disabled > 0) parts.push(t('dash.disabledN', { n: s.disabled }))
  return parts.join(' · ')
}

function NetRow({ family, ip, local, checking }: { family: string; ip: string; local: boolean; checking: boolean }) {
  const { t } = useI18n()
  const usable = !!ip
  const tone: Tone = usable ? 'ok' : local ? 'warn' : 'neutral'
  const text = usable ? t('dash.netUsable') : checking ? t('dash.netChecking') : local ? t('dash.netLocalOnly') : t('dash.netNone')
  return (
    <div className="net-row">
      <div>
        <strong>{family}</strong>
        <div className="mono small">{ip || '–'}</div>
      </div>
      <Badge tone={tone}>{text}</Badge>
    </div>
  )
}

/** Runs `load` once, after the first paint, so the dashboard itself stays quick. */
function useLate<T>(load: () => Promise<T>): { data: T | null; failed: boolean } {
  const [state, setState] = useState<{ data: T | null; failed: boolean }>({ data: null, failed: false })
  useEffect(() => {
    let alive = true
    const id = window.setTimeout(() => {
      load().then(
        (data) => alive && setState({ data, failed: false }),
        () => alive && setState({ data: null, failed: true }),
      )
    }, 250)
    return () => {
      alive = false
      window.clearTimeout(id)
    }
  }, [])
  return state
}

function AITile() {
  const { t } = useI18n()
  const { data, failed } = useLate(() => api.get<AIView>('/api/ai'))
  const bound = data ? data.nodes.filter((n) => n.bound).length : 0
  const tone: Tone = !data ? 'neutral' : data.problems.length > 0 ? 'warn' : data.enabled ? 'ok' : 'neutral'
  return (
    <Link to="/ai" className="tile">
      <span className="tile-label">{t('dash.ai')}</span>
      <span className="tile-value">
        {data ? <Badge tone={tone}>{data.enabled ? t('dash.aiOn', { n: bound }) : t('dash.aiOff')}</Badge> : failed ? <Badge>{t('dash.webFailed')}</Badge> : <span className="muted small">{t('common.loading')}</span>}
      </span>
      <span className="tile-sub">
        {data?.exit ? t('dash.aiExit', { name: data.exit.name }) : data ? t('ai.noExit') : ''}
        {data && data.problems.length > 0 ? ` · ${t('dash.aiProblems', { n: data.problems.length })}` : ''}
      </span>
      <span className="tile-go" aria-hidden="true">→</span>
    </Link>
  )
}

function WebTile() {
  const { t } = useI18n()
  const { data, failed } = useLate<PanelHTTPSReport>(() => loadPanelReport())
  const h = data ? panelHealth(data) : null
  return (
    <Link to="/system?tab=network" className="tile">
      <span className="tile-label">{t('dash.web')}</span>
      <span className="tile-value">{h ? <Badge tone={h.tone}>{t(h.key)}</Badge> : failed ? <Badge>{t('dash.webFailed')}</Badge> : <span className="muted small">{t('dash.webChecking')}</span>}</span>
      <span className="tile-sub mono">{data?.url ?? data?.domain ?? ''}</span>
      <span className="tile-go" aria-hidden="true">→</span>
    </Link>
  )
}
